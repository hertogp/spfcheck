defmodule Spf.Eval do
  @moduledoc """
  Functions to evaluate an SPF context

  TODO
  [ ] expand macro's on demand, not beforehand
  [ ] fix dns stats, make it public and call when needed
      - DNS.resolve MUST always count the dnsq's since there is no limit
  [ ] rename tokens.ex to lexer.ex
  """

  alias Spf.DNS
  import Spf.Context

  # Helpers

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
          |> Map.put(:explanation, explainp(ctx, explain))
      end
    else
      ctx
    end
  end

  defp explainp(ctx, explain) do
    case Spf.exp_tokens(explain) do
      {:error, _, _, _, _, _} ->
        ""

      {:ok, [{:exp_str, _tokens, _range} = exp_str], _, _, _, _} ->
        Spf.Parser.expand(ctx, exp_str)
    end
  end

  defp check_limits(ctx) do
    # only check for original SPF record, so we donot prematurely stop processing
    if ctx.nth == 0 do
      ctx =
        if ctx.num_dnsm > ctx.max_dnsm do
          Map.put(ctx, :error, :too_many_dnsm)
          |> Map.put(:reason, "too many DNS mechanisms used #{ctx.num_dnsm}")
          |> Map.put(:verdict, :permerror)
          |> then(fn ctx -> log(ctx, :eval, :error, ctx.reason) end)
        else
          ctx
        end

      if ctx.num_dnsv > ctx.max_dnsv do
        Map.put(ctx, :error, :too_many_dnsv)
        |> Map.put(:reason, "too many VOID DNS queries seen #{ctx.num_dnsv}")
        |> Map.put(:verdict, :permerror)
        |> then(fn ctx -> log(ctx, :eval, :error, ctx.reason) end)
      else
        ctx
      end
    else
      ctx
    end
  end

  defp match(%{error: error} = ctx, _term, _tail) when error != nil,
    # a fatal error was recorded, so bailout
    do: bailout(ctx)

  defp match(ctx, {_m, _token, range} = _term, tail) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-4.6.2
    # {_pfx, qlist} = Iptrie.lookup(ctx.ipt, ctx.ip) || {nil, nil}

    verdict = verdict(ctx)

    if verdict do
      # ctx.ip has a match, so set corresponding result
      log(ctx, :eval, :note, "#{String.slice(ctx.spf, range)} - matches #{ctx.ip}")
      |> tick(:num_checks)
      |> Map.put(:verdict, verdict)
      |> Map.put(:reason, "spf[#{ctx.nth}] #{String.slice(ctx.spf, range)}")
    else
      # no match, continue evaluation
      log(ctx, :eval, :info, "#{String.slice(ctx.spf, range)} - no match")
      |> tick(:num_checks)
      |> evalp(tail)
    end
  end

  defp validate(name, ctx, {:ptr, [q, domain], _} = term) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-5.5
    {ctx, dns} = DNS.resolve(ctx, name, type: ctx.atype)

    case validate?(dns, ctx.ip, name, domain) do
      true ->
        addip(ctx, [ctx.ip], [32, 128], {q, ctx.nth, term})
        |> log(:eval, :info, "validated: #{name}, #{ctx.ip} for #{domain}")

      false ->
        log(ctx, :eval, :info, "not validated: #{name}, #{ctx.ip} for #{domain}")
    end
  end

  # a name is validated iff it's ip == <ip> && name endswith? domain
  defp validate?({:error, _}, _ip, _name, _domain),
    do: false

  defp validate?({:ok, rrs}, ip, name, domain) do
    pfx = Pfx.new(ip)

    if Enum.any?(rrs, fn ip -> Pfx.member?(ip, pfx) end) do
      String.downcase(name)
      |> String.ends_with?(String.downcase(domain))
    else
      false
    end
  end

  def set_p_macro(ctx) do
    # ctx.macro[?p] = shortest validated name possible, or "unknown"
    # TODO: refactor this abomination!
    {ctx, dns} = DNS.resolve(ctx, Pfx.dns_ptr(ctx.ip), type: :ptr, stats: false)

    domain = Spf.DNS.normalize(ctx.domain)

    pvalue =
      case dns do
        {:error, _reason} ->
          "unknown"

        {:ok, rrs} ->
          Enum.take(rrs, 10)
          |> Enum.map(fn name -> Spf.DNS.normalize(name) end)
          |> Enum.filter(fn name -> String.ends_with?(name, domain) end)
          |> Enum.map(fn name ->
            {name, Spf.DNS.resolve(ctx, name, type: ctx.atype, stats: false) |> elem(1)}
          end)
          |> Enum.filter(fn {name, dns} -> validate?(dns, ctx.ip, name, domain) end)
          |> Enum.map(fn {name, _dns} -> name end)
          |> Enum.sort(&(byte_size(&1) <= byte_size(&2)))
          |> List.first()
      end

    pvalue =
      case pvalue do
        nil -> "unknown"
        str -> str
      end

    put_in(ctx, [:macro, ?p], pvalue)
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
          log(ctx, :name, :error, "domain error: #{reason}")
          |> Map.put(:error, :illegal_domain)
          |> Map.put(:reason, reason)
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
          Map.put(ctx, :error, :no_spf)
          |> Map.put(:reason, "no SPF record found")
          |> then(fn ctx -> log(ctx, :check, :note, "no SPF record found") end)

        [spf] ->
          if Spf.is_ascii?(spf) do
            Map.put(ctx, :spf, spf)
          else
            Map.put(ctx, :error, :non_ascii_spf)
            |> Map.put(:reason, "SPF contains non-ascii characters")
            |> then(fn ctx -> log(ctx, :error, :check, ctx.reason) end)
          end

        list ->
          Map.put(ctx, :error, :many_spf)
          |> Map.put(:reason, "too many SPF records found (#{length(list)})")
          |> then(fn ctx -> log(ctx, :check, :error, ctx.reason) end)
      end
    end
  end

  # API

  def evaluate(ctx) do
    ctx
    |> check_domain()
    |> Spf.grep()
    |> check_spf()
    |> Spf.Parser.parse()
    |> eval()
  end

  defp bailout(%{error: error} = ctx) when error != nil do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-4.3
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-4.4
    case error do
      :illegal_domain -> Map.put(ctx, :verdict, :none)
      # TODO: this should be handled by case dns of ...
      :illegal_name -> Map.put(ctx, :verdict, :none)
      :include_loop -> Map.put(ctx, :verdict, :permerror)
      :many_spf -> Map.put(ctx, :verdict, :permerror)
      :no_redir_domain -> Map.put(ctx, :verdict, :permerror)
      :no_redir_spf -> Map.put(ctx, :verdict, :permerror)
      :no_spf -> Map.put(ctx, :verdict, :none)
      :non_ascii_spf -> Map.put(ctx, :verdict, :permerror)
      :nxdomain -> Map.put(ctx, :verdict, :none)
      :redirect_loop -> Map.put(ctx, :verdict, :permerror)
      :repeated_modifier -> Map.put(ctx, :verdict, :permerror)
      :servfail -> Map.put(ctx, :verdict, :temperror)
      :syntax_error -> Map.put(ctx, :verdict, :permerror)
      :timeout -> Map.put(ctx, :verdict, :temperror)
      :too_many_dnsm -> Map.put(ctx, :verdict, :permerror)
      :too_many_dnsv -> Map.put(ctx, :verdict, :permerror)
      :too_many_mtas -> Map.put(ctx, :verdict, :permerror)
      :zero_answers -> Map.put(ctx, :verdict, :none)
    end
  end

  defp eval(%{error: error} = ctx) when error != nil,
    do: bailout(ctx)

  defp eval(ctx) do
    evalp(ctx, ctx.ast)
    |> explain()
    |> Map.put(:duration, (DateTime.utc_now() |> DateTime.to_unix()) - ctx.macro[?t])
    |> check_limits()
  end

  # Eval Terms

  # Nomore TermS
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
        Map.put(ctx, :error, reason)
        |> Map.put(:reason, "DNS error #{domain} - #{reason}}")
        |> then(fn ctx -> log(ctx, :error, :warn, ctx.reason) end)

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
        Map.put(ctx, :error, reason)
        |> Map.put(:reason, "DNS error #{domain} - #{reason}}")
        |> then(fn ctx -> log(ctx, :error, :warn, ctx.reason) end)

      {:ok, rrs} ->
        ctx =
          Enum.map(rrs, fn {_pref, name} -> name end)
          |> Enum.take(10)
          |> Enum.reduce(ctx, fn name, acc -> evalname(acc, name, dual, {q, ctx.nth, term}) end)
          |> log(:dns, :debug, "MX #{domain} #{inspect({q, ctx.nth, term})} added")

        if length(rrs) > 10 do
          # https://www.rfc-editor.org/rfc/rfc7208.html#section-4.6.4
          Map.put(ctx, :error, :too_many_mtas)
          |> Map.put(:reason, "too many mta's for #{String.slice(ctx.spf, range)}")
          |> then(fn ctx -> log(ctx, :eval, :error, ctx.reason) end)
        else
          ctx
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
        Map.put(ctx, :error, reason)
        |> Map.put(:reason, "DNS error #{domain} - #{reason}}")
        |> then(fn ctx -> log(ctx, :error, :warn, ctx.reason) end)

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
        Map.put(ctx, :error, reason)
        |> Map.put(:reason, "DNS error #{domain} - #{reason}}")
        |> then(fn ctx -> log(ctx, :error, :warn, ctx.reason) end)

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
    if ctx.map[domain] do
      Map.put(ctx, :error, :include_loop)
      |> Map.put(:reason, "included #{domain} seen before in spf #{ctx.map[domain]}")
      |> then(fn ctx -> log(ctx, :eval, :warn, ctx.reason) end)
      |> bailout()
    else
      ctx =
        log(ctx, :eval, :note, "#{String.slice(ctx.spf, range)} - recurse")
        |> push(domain)
        |> evaluate()

      case ctx.verdict do
        v when v in [:neutral, :fail, :softfail] ->
          ctx = pop(ctx)

          log(ctx, :eval, :info, "#{String.slice(ctx.spf, range)} - no match")
          |> evalp(tail)

        :pass ->
          ctx = pop(ctx)

          ctx
          |> Map.put(:verdict, qualify(q))
          |> log(:eval, :info, "#{String.slice(ctx.spf, range)} - match")
          |> Map.put(:reason, "spf[#{ctx.nth}] #{String.slice(ctx.spf, range)} - matched")

        v when v in [:none, :permerror] ->
          ctx = pop(ctx)

          ctx
          |> Map.put(:verdict, :permerror)
          |> log(:eval, :error, "#{String.slice(ctx.spf, range)} - permanent error")
          |> Map.put(:reason, "#{String.slice(ctx.spf, range)} - permerror")

        :temperror ->
          ctx = pop(ctx)

          ctx
          |> log(:eval, :warn, "#{String.slice(ctx.spf, range)} - temp error")
      end
    end
  end

  # All
  defp evalp(ctx, [{:all, [q], _range} = term | tail]) do
    log(ctx, :eval, :info, "SPF match by #{List.to_string([q])}all")
    |> tick(:num_checks)
    |> addip(ctx.ip, [32, 128], {q, ctx.nth, term})
    |> match(term, tail)
  end

  # REDIRECT
  defp evalp(ctx, [{:redirect, [:einvalid], range} | _tail]) do
    Map.put(ctx, :error, :no_redir_domain)
    |> Map.put(:reason, "invalid domain in #{String.slice(ctx.spf, range)}")
    |> then(fn ctx -> log(ctx, :eval, :error, ctx.reason) end)
    |> bailout()
  end

  defp evalp(ctx, [{:redirect, [domain], _range} = term | tail]) do
    # spec 6.1
    # - if redirect domain has no SPF -> permerror
    # - if redirect domain is mailformed -> permerror
    # - otherwise its result is the result for this SPF
    if ctx.map[domain] do
      Map.put(ctx, :error, :redirect_loop)
      |> Map.put(:reason, "redirect #{domain} seen before in spf #{ctx.map[domain]}")
      |> then(fn ctx -> log(ctx, :eval, :warn, ctx.reason) end)
      |> bailout()
    else
      nth = ctx.num_spf

      ctx =
        test(ctx, :error, term, length(tail) > 0, "terms after redirect?")
        |> log(:eval, :note, "redirecting to #{domain}")
        |> tick(:num_spf)
        |> Map.put(:map, Map.merge(ctx.map, %{nth => domain, domain => nth}))
        |> Map.put(:domain, domain)
        |> Map.put(:f_include, ctx.f_include)
        |> Map.put(:f_redirect, false)
        |> Map.put(:f_all, false)
        |> Map.put(:nth, nth)
        |> Map.put(:macro, macros(domain, ctx.ip, ctx.sender, ctx.helo))
        |> Map.put(:ast, [])
        |> Map.put(:spf, "")
        |> Map.put(:explain, nil)
        |> evaluate()

      if ctx.error in [:no_spf, :nxdomain] do
        Map.put(ctx, :error, :no_redir_spf)
        |> Map.put(:reason, "no SPF found for #{domain}")
        |> then(fn ctx -> log(ctx, :eval, :error, ctx.reason) end)
        |> bailout()
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
