defmodule Spf.Eval do
  @moduledoc """
  Functions to evaluate an SPF context

  TODO
  [ ] expand macro's on demand, not beforehand
  [ ] fix dns stats, make it public and call when needed
      - DNS.resolve MUST always count the dnsq's since there is no limit
  """

  alias Spf.DNS
  import Spf.Context

  # Helpers

  defp ascii?(string) when is_binary(string),
    do: string == for(<<c <- string>>, c in 0..127, into: "", do: <<c>>)

  defp ascii?(_string),
    do: false

  defp evalname(ctx, domain, dual, value) do
    {ctx, dns} = DNS.resolve(ctx, domain, type: ctx.atype)

    case dns do
      {:error, reason} ->
        log(ctx, :eval, :warn, "#{ctx.atype} #{domain} - DNS error #{inspect(reason)}")

      {:ok, rrs} ->
        addip(ctx, rrs, dual, value)
    end
  end

  defp explain(ctx) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-6.2
    # - donot track void answers
    if ctx.verdict == :fail and ctx.explain do
      {_token, [domain], _range} = ctx.explain
      {ctx, dns} = DNS.resolve(ctx, domain, type: :txt, stats: false)

      case dns do
        {:error, reason} ->
          log(ctx, :dns, :warn, "txt #{domain} - DNS error #{reason}")

        {:ok, list} when length(list) > 1 ->
          log(ctx, :dns, :error, "txt #{domain} - too many explain txt records #{inspect(list)}")

        {:ok, [explain]} ->
          log(ctx, :dns, :info, "txt #{domain} -> '#{explain}'")
          |> Map.put(:explanation, Spf.Parser.explain(ctx, explain))
      end
    else
      ctx
    end
  end

  defp check_limits(ctx) do
    # only check for original SPF record, so we donot prematurely stop processing
    if ctx.nth == 0 do
      ctx =
        if ctx.num_dnsm > ctx.max_dnsm do
          error(ctx, :too_many_dnsm, "too many DNS mechanisms used (#{ctx.num_dnsm})", :permerror)
        else
          ctx
        end

      if ctx.num_dnsv > ctx.max_dnsv do
        error(ctx, :too_many_dnsv, "too many VOID DNS queries seen (#{ctx.num_dnsv})", :permerror)
      else
        ctx
      end
    else
      ctx
    end
  end

  defp match(%{error: error} = ctx, _term, _tail) when error != nil,
    # a fatal error was recorded, so bailout
    do: ctx

  defp match(ctx, {_q, _token, range} = _term, tail) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-4.6.2
    # {_pfx, qlist} = Iptrie.lookup(ctx.ipt, ctx.ip) || {nil, nil}

    verdict = verdict(ctx)

    if verdict do
      # ctx.ip has a match, so set corresponding result and we're done
      log(ctx, :eval, :note, "#{spf_term(ctx, range)} - matches #{ctx.ip}")
      |> tick(:num_checks)
      |> Map.put(:verdict, verdict)
      |> Map.put(:reason, "#{spf_term(ctx, range)}")
    else
      # no match, so continue evaluation
      log(ctx, :eval, :info, "#{spf_term(ctx, range)} - no match")
      |> tick(:num_checks)
      |> evalp(tail)
    end
  end

  defp validate(name, ctx, {:ptr, [q, domain], _} = term) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-5.5
    {ctx, dns} = DNS.resolve(ctx, name, type: ctx.atype)

    case validate?(dns, ctx.ip, name, domain, true) do
      true ->
        addip(ctx, [ctx.ip], [32, 128], {q, ctx.nth, term})
        |> log(:eval, :info, "validated: #{name}, #{ctx.ip} for #{domain}")

      false ->
        log(ctx, :eval, :info, "not validated: #{name}, #{ctx.ip} for #{domain}")
    end
  end

  defp verdict(ctx) when is_map(ctx) do
    with {_pfx, qlist} <- Iptrie.lookup(ctx.ipt, ctx.ip),
         {term, _} <- List.keytake(qlist, ctx.nth, 1),
         q <- elem(term, 0) do
      qualify(q)
    else
      _ -> nil
    end
  end

  defp qualify(qualifier) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-4.6.2
    case qualifier do
      ?+ -> :pass
      ?- -> :fail
      ?~ -> :softfail
      ?? -> :neutral
    end
  end

  defp check_domain(ctx) do
    # check domain, if not a legal fqdn -> evaluation result is :none
    # since there is no domain to actually check
    if ctx.error do
      ctx
    else
      case Spf.DNS.valid?(ctx.domain) do
        {:ok, _domain} ->
          ctx

        {:error, reason} ->
          error(ctx, :illegal_domain, "domain error (#{reason})", :none)
      end
    end
  end

  defp check_spf(ctx) do
    # either set :error, or set :spf to single spf string

    if ctx.error do
      ctx
    else
      case ctx.spf do
        [] ->
          error(ctx, :no_spf, "no SPF record found", :none)

        [spf] ->
          if ascii?(spf) do
            Map.put(ctx, :spf, spf)
          else
            error(ctx, :non_ascii_spf, "SPF contains non-ascii characters", :permerror)
          end

        list ->
          error(ctx, :too_many_spf, "too many SPF records found (#{length(list)})", :permerror)
      end
    end
  end

  defp grep_spf(ctx) when is_map(ctx) do
    {ctx, result} = Spf.DNS.resolve(ctx, ctx.domain, type: :txt, stats: false)

    ctx =
      case Spf.DNS.grep(result, &spf?/1) do
        {:ok, spf} ->
          Map.put(ctx, :spf, spf)

        {:error, :timeout} ->
          error(ctx, :timeout, "DNS error (timeout)", :temperror)
          |> Map.put(:spf, [])

        {:error, reason} when reason in [:nxdomain, :zero_answers, :illegal_name] ->
          error(ctx, reason, "DNS error (#{reason})", :none)
          |> Map.put(:spf, [])

        {:error, reason} ->
          IO.inspect(reason, label: :grep_spf_reason)

          Map.put(ctx, :error, reason)
          |> Map.put(:spf, [])
      end

    ctx
    |> Spf.Context.log(:spf, :note, "SPF (#{ctx.nth}): #{inspect(ctx.spf)}")
  end

  # API

  @spec spf?(binary) :: boolean
  def spf?(str) when is_binary(str),
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-4.5
    do: String.match?(str, ~r/^\s*v=spf1(\s|$)/i)

  def spf?(_),
    do: false

  def check(sender, opts \\ []) do
    Spf.Context.new(sender, opts)
    |> Spf.Eval.evaluate()
  end

  def evaluate(ctx) do
    ctx
    |> check_domain()
    |> grep_spf()
    |> check_spf()
    |> Spf.Parser.parse()
    |> eval()
  end

  # a name is validated iff it's ip == <ip> && possibly when name endswith? domain
  def validate?({:error, _}, _ip, _name, _domain, _exact),
    do: false

  def validate?({:ok, rrs}, ip, name, domain, exact) do
    pfx = Pfx.new(ip)

    if Enum.any?(rrs, fn ip -> Pfx.member?(ip, pfx) end) do
      if exact do
        String.downcase(name)
        |> String.ends_with?(String.downcase(domain))
      else
        true
      end
    else
      false
    end
  end

  # Eval Terms

  defp eval(%{error: error} = ctx) when error != nil,
    do: ctx

  defp eval(ctx) do
    evalp(ctx, ctx.ast)
    |> explain()
    |> Map.put(:duration, (DateTime.utc_now() |> DateTime.to_unix()) - ctx.t0)
    |> check_limits()
  end

  # Nomore Terms
  defp evalp(ctx, []),
    do: ctx

  # A
  defp evalp(ctx, [{:a, [q, domain, dual], _range} = term | tail]) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-5.3
    {ctx, dns} = DNS.resolve(ctx, domain, type: ctx.atype)

    case dns do
      {:error, reason} when reason in [:nxdomain, :zero_answers, :illegal_name] ->
        ctx

      {:error, reason} ->
        error(ctx, reason, "DNS error #{domain} - #{reason}", :temperror)

      {:ok, rrs} ->
        addip(ctx, rrs, dual, {q, ctx.nth, term})
    end
    |> match(term, tail)
  end

  # MX
  defp evalp(ctx, [{:mx, [q, domain, dual], range} = term | tail]) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-5.4
    {ctx, dns} = DNS.resolve(ctx, domain, type: :mx)

    case dns do
      {:error, reason} when reason in [:nxdomain, :zero_answers, :illegal_name] ->
        ctx

      {:error, reason} ->
        error(ctx, reason, "DNS error #{domain} - #{reason}", :temperror)

      {:ok, rrs} ->
        if length(rrs) > 10 do
          # https://www.rfc-editor.org/rfc/rfc7208.html#section-4.6.4
          error(ctx, :too_many_mtas, "too many mta's for #{spf_term(ctx, range)}", :permerror)
        else
          Enum.map(rrs, fn {_pref, name} -> name end)
          |> Enum.take(10)
          |> Enum.reduce(ctx, fn name, acc -> evalname(acc, name, dual, {q, ctx.nth, term}) end)
          |> log(:dns, :debug, "MX #{domain} #{inspect({q, ctx.nth, term})} added")
        end
    end
    |> match(term, tail)
  end

  # PTR
  defp evalp(ctx, [{:ptr, [_q, domain], _range} = term | tail]) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-5.5
    # https://www.rfc-editor.org/errata/eid4751
    domain = Spf.DNS.normalize(domain)
    {ctx, dns} = DNS.resolve(ctx, Pfx.dns_ptr(ctx.ip), type: :ptr)

    case dns do
      {:error, reason} when reason in [:nxdomain, :zero_answers, :illegal_name] ->
        ctx

      {:error, reason} ->
        error(ctx, reason, "DNS error #{domain} - #{reason}", :temperror)

      {:ok, rrs} ->
        # https://www.rfc-editor.org/errata/eid5227
        Enum.map(rrs, fn name -> Spf.DNS.normalize(name) end)
        |> Enum.filter(fn name -> String.ends_with?(name, domain) end)
        |> Enum.take(10)
        |> Enum.reduce(ctx, fn name, acc -> validate(name, acc, term) end)
    end
    |> match(term, tail)
  end

  # EXISTS
  defp evalp(ctx, [{:exists, [q, domain], _range} = term | tail]) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-5.7
    {ctx, dns} = DNS.resolve(ctx, domain, type: :a)

    case dns do
      {:error, reason} when reason in [:nxdomain, :zero_answers, :illegal_name] ->
        ctx

      {:error, reason} ->
        error(ctx, reason, "DNS error #{domain} - #{reason}", :temperror)

      {:ok, rrs} ->
        log(ctx, :eval, :info, "DNS #{inspect(rrs)}")
        |> addip(ctx.ip, [32, 128], {q, ctx.nth, term})
    end
    |> match(term, tail)
  end

  # IP4/6
  defp evalp(ctx, [{ip, [q, pfx], _range} = term | tail]) when ip in [:ip4, :ip6] do
    addip(ctx, [pfx], [32, 128], {q, ctx.nth, term})
    |> match(term, tail)
  end

  # INCLUDE
  defp evalp(ctx, [{:include, [q, domain], range} = _term | tail]) do
    # if ctx.map[domain] do
    if loop?(ctx, domain) do
      error(
        ctx,
        :loop,
        "loop detected: #{ctx.domain} cannot include #{domain}",
        :permerror
      )
    else
      ctx =
        log(ctx, :eval, :note, "#{spf_term(ctx, range)} - recurse")
        |> push(domain)
        |> evaluate()

      case ctx.verdict do
        v when v in [:neutral, :fail, :softfail] ->
          ctx = pop(ctx)

          log(ctx, :eval, :info, "#{spf_term(ctx, range)} - no match")
          |> evalp(tail)

        :pass ->
          ctx = pop(ctx)

          ctx
          |> Map.put(:verdict, qualify(q))
          |> log(:eval, :info, "#{spf_term(ctx, range)} - match")
          |> Map.put(:reason, "#{spf_term(ctx, range)} - matched")

        v when v in [:none, :permerror] ->
          ctx = pop(ctx)
          error(ctx, :include, "#{spf_term(ctx, range)} - permanent error", :permerror)

        :temperror ->
          ctx = pop(ctx)

          ctx
          |> log(:eval, :warn, "#{spf_term(ctx, range)} - temp error")
      end
    end
  end

  # All
  defp evalp(ctx, [{:all, [q], range} = term | tail]) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-5.1
    log(ctx, :eval, :info, "#{spf_term(ctx, range)} - matches")
    |> tick(:num_checks)
    |> addip(ctx.ip, [32, 128], {q, ctx.nth, term})
    |> match(term, tail)
  end

  # REDIRECT
  defp evalp(ctx, [{:redirect, [:einvalid], range} | _tail]) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-6.1
    error(ctx, :no_redir_domain, "#{spf_term(ctx, range)} - invalid domain", :permerror)
  end

  defp evalp(ctx, [{:redirect, [domain], range} = term | tail]) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-6.1
    # - if redirect domain has no SPF -> permerror
    # - if redirect domain is mailformed -> permerror
    # - otherwise its result is the result for this SPF
    # if ctx.map[domain] do
    if loop?(ctx, domain) do
      error(
        ctx,
        :loop,
        "loop detected: #{ctx.domain} cannot redirect to #{domain}",
        :permerror
      )
    else
      ctx =
        test(ctx, :error, term, length(tail) > 0, "terms after #{spf_term(ctx, range)}?")
        |> log(:eval, :note, "#{spf_term(ctx, range)} - redirecting to #{domain}")
        |> redirect(domain)
        |> evaluate()

      if ctx.error in [:no_spf, :nxdomain] do
        error(ctx, :no_redir_spf, "no SPF found for #{domain}", :permerror)
      else
        ctx
      end
    end
  end

  # TERM?
  defp evalp(ctx, [term | tail]) do
    log(ctx, :eval, :error, "internal error, eval is missing a handler for #{inspect(term)}")
    |> evalp(tail)
  end
end
