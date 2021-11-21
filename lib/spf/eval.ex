defmodule Spf.Eval do
  @moduledoc """
  Functions to evaluate an SPF context.

  """

  alias Spf.DNS
  import Spf.Context

  @type dns_result :: Spf.DNS.dns_result()
  @type context :: Spf.Context.t()

  # API

  @doc """
  Say whether `str` contains the start of an SPF string.

  Leading whitespace is not considered an error, although technically it is a
  syntax error.

  """
  @spec spf?(binary) :: boolean
  def spf?(str) when is_binary(str),
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-4.5
    do: String.match?(str, ~r/^\s*v=spf1(\s|$)/i)

  def spf?(_),
    do: false

  @doc """
  Given a [`context`](`t:Spf.Context.t/0`) retrieve and evaluate the associated SPF record.

  After an (attempted) evaluation, returns an updated context where:
  - `:verdict` will be one of `:pass, :fail, :softfail, :neutral`
  - `:reason` show the mechanism responsible for the verdict
  - `:explanation` the expanded explain-string (if possible and applicable)
  - `:error` in case one occurred
  - `:ipt` which maps the prefixes seen during evaluation to their source
  - `:msg` which lists log messages accumulated during evaluation

  and other fields containing information gathered during the evaluation.

  The context is passed around accumulating information and tracks the state of
  the evaluation. Its `:log` is either `nil` or points to a `log_function/4`
  that then called with the `context`, `facility`, `severity` and a `message`
  so it can dump it to screen or somewhere else.

  """
  @spec evaluate(context) :: context
  def evaluate(ctx) do
    ctx
    |> check_domain()
    |> grep_spf()
    |> Spf.Parser.parse()
    |> eval()

    # |> check_spf()
  end

  @doc """
  Returns true if `name` is a validated name for given `domain`.

  The [`dns_result`](`t:dns_result/0`) should contain the ip addresses
  associated with given `name`. If any of the ip adresss match the given `ip`,
  the `name` is a validated domain name for given `domain`.

  If the `exact` flag is true, then the `name` is also required to
  end with given `domain` as well.

  Note that when trying to validate names during the expansion of the p-marco,
  this flag will be false.

  """
  # a name is validated iff it's ip == <ip> && possibly when name endswith? domain
  @spec validate?(dns_result, binary, binary, binary, boolean) :: boolean
  def validate?(dns_result, ip, name, domain, exact)

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

  def validate?({:error, _}, _ip, _name, _domain, _exact),
    do: false

  # Helpers

  @spec ascii?(binary) :: boolean
  defp ascii?(string) when is_binary(string),
    do: string == for(<<c <- string>>, c < 128, into: "", do: <<c>>)

  @spec evalname(context, binary, list, any) :: context
  defp evalname(ctx, domain, dual, value) do
    {ctx, dns} = DNS.resolve(ctx, domain, type: ctx.atype)

    case dns do
      {:error, reason} ->
        log(ctx, :eval, :warn, "#{ctx.atype} #{domain} - DNS error #{inspect(reason)}")

      {:ok, rrs} ->
        addip(ctx, rrs, dual, value)
    end
  end

  @spec explain(context) :: context
  defp explain(ctx) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-6.2
    # - donot track void answers
    # - get & store the explain-string pointed to by the ctx.explain token
    # - expand explain-string and store as ctx.explanation
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
          |> Map.put(:explain_string, explain)
          |> Spf.Parser.explain()
      end
    else
      ctx
    end
  end

  @spec check_limits(context) :: context
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

  @spec match(context, tuple, list) :: context
  defp match(%{error: error} = ctx, _term, _tail) when error != nil,
    # a fatal error was already recorded, so bailout
    do: ctx

  defp match(ctx, {_q, _token, range} = _term, tail) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-4.6.2

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

  @spec validate(binary, context, tuple) :: context
  defp validate(name, ctx, {:ptr, [q, domain], range} = _term) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-5.5
    {ctx, dns} = DNS.resolve(ctx, name, type: ctx.atype)

    case validate?(dns, ctx.ip, name, domain, true) do
      true ->
        addip(ctx, [ctx.ip], [32, 128], {q, ctx.nth, spf_term(ctx, range)})
        |> log(:eval, :info, "validated: #{name}, #{ctx.ip} for #{domain}")

      false ->
        log(ctx, :eval, :info, "not validated: #{name}, #{ctx.ip} for #{domain}")
    end
  end

  @spec verdict(context) :: nil | atom
  defp verdict(ctx) do
    # used by match/1 to check if we currently have a match
    # - ipt[prefix] -> [{q, nth, token}] => list of tokens and SPF-id that added the prefix
    # - the token contains the qualifier that, if matched, says what the result should be
    # notes:
    # - prefixes can be contributed multiple times by Nxterms in Mxrecords
    # - the last {token, nth} to do so, is listed first
    # - so only check for the first token for the current ctx.nth
    # - having verdict does not necessarily stop evaluation (e.g. when inside an include)
    with {_pfx, qlist} <- Iptrie.lookup(ctx.ipt, ctx.ip),
         {data, _} <- List.keytake(qlist, ctx.nth, 1),
         q <- elem(data, 0) do
      qualify(q)
    else
      _ -> nil
    end
  end

  @spec qualify(pos_integer()) :: atom
  defp qualify(qualifier) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-4.6.2
    case qualifier do
      ?+ -> :pass
      ?- -> :fail
      ?~ -> :softfail
      ?? -> :neutral
    end
  end

  @spec check_domain(context) :: context
  defp check_domain(ctx) do
    # check domain, if not a legal fqdn -> evaluation result is :none
    # since there is no domain to actually check
    if ctx.error do
      ctx
    else
      case Spf.DNS.check_domain(ctx.domain) do
        {:ok, _domain} ->
          ctx

        {:error, reason} ->
          error(ctx, :illegal_domain, "domain error (#{reason})", :none)
      end
    end
  end

  @spec grep_spf(context) :: context
  defp grep_spf(ctx) do
    # either set ctx.spf to an SPF record, or set ctx.error to some atom error
    {ctx, result} = Spf.DNS.resolve(ctx, ctx.domain, type: :txt, stats: false)

    case Spf.DNS.filter(result, &spf?/1) do
      {:ok, []} ->
        error(ctx, :no_spf, "no SPF record found", :none)

      {:ok, [spf]} ->
        if ascii?(spf),
          do: Map.put(ctx, :spf, spf),
          else: error(ctx, :non_ascii_spf, "SPF contains non-ascii characters", :permerror)

      {:ok, list} ->
        error(ctx, :too_many_spf, "too many SPF records found (#{length(list)})", :permerror)

      {:error, :timeout} ->
        error(ctx, :timeout, "txt #{ctx.domain} - DNS error (timeout)", :temperror)

      {:error, :servfail} ->
        error(ctx, :servfail, "txt #{ctx.domain} - DNS error (servfail)", :temperror)

      {:error, :nxdomain} ->
        error(ctx, :nxdomain, "txt #{ctx.domain} - DNS error (nxdomain)", :none)

      {:error, :zero_answers} ->
        error(ctx, :zero_answers, "txt #{ctx.domain} - DNS error (zero answers)", :none)

      {:error, :illegal_name} ->
        error(ctx, :illegal_name, "txt #{ctx.domain} - DNS error (illegal name)", :none)

      {:error, reason} ->
        Map.put(ctx, :error, reason)
    end
  end

  # Eval Terms

  @spec eval(Spf.Context.t()) :: Spf.Context.t()
  defp eval(%{error: error} = ctx) when error != nil,
    do: ctx

  defp eval(ctx) do
    evalp(ctx, ctx.ast)
    |> explain()
    |> Map.put(:duration, (DateTime.utc_now() |> DateTime.to_unix()) - ctx.t0)
    |> check_limits()
  end

  @spec evalp(context, list) :: context
  defp evalp(ctx, []),
    # Nomore Terms
    do: ctx

  # A
  defp evalp(ctx, [{:a, [q, domain, dual], range} = term | tail]) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-5.3
    {ctx, dns} = DNS.resolve(ctx, domain, type: ctx.atype)

    case dns do
      {:error, reason} when reason in [:nxdomain, :zero_answers, :illegal_name] ->
        ctx

      {:error, reason} ->
        error(ctx, reason, "DNS error #{domain} - #{reason}", :temperror)

      {:ok, rrs} ->
        addip(ctx, rrs, dual, {q, ctx.nth, spf_term(ctx, range)})
    end
    |> match(term, tail)
  end

  # All
  defp evalp(ctx, [{:all, [q], range} = _term | _tail]) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-5.1
    log(ctx, :eval, :info, "#{spf_term(ctx, range)} - matches")
    |> tick(:num_checks)
    |> Map.put(:verdict, qualify(q))
    |> Map.put(:reason, "#{spf_term(ctx, range)}")
  end

  # EXISTS
  defp evalp(ctx, [{:exists, [q, domain], range} = term | tail]) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-5.7
    {ctx, dns} = DNS.resolve(ctx, domain, type: :a)

    case dns do
      {:error, reason} when reason in [:nxdomain, :zero_answers, :illegal_name] ->
        ctx

      {:error, reason} ->
        error(ctx, reason, "DNS error #{domain} - #{reason}", :temperror)

      {:ok, rrs} ->
        log(ctx, :eval, :info, "DNS #{inspect(rrs)}")
        |> addip(ctx.ip, [32, 128], {q, ctx.nth, spf_term(ctx, range)})
    end
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

  # IP4/6
  defp evalp(ctx, [{ip, [q, pfx], range} = term | tail]) when ip in [:ip4, :ip6] do
    addip(ctx, [pfx], [32, 128], {q, ctx.nth, spf_term(ctx, range)})
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
          |> Enum.reduce(ctx, fn name, acc ->
            evalname(acc, name, dual, {q, ctx.nth, spf_term(ctx, range)})
          end)
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

  # REDIRECT
  defp evalp(ctx, [{:redirect, [:einvalid], range} | _tail]) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-6.1
    error(ctx, :no_redir_domain, "#{spf_term(ctx, range)} - invalid domain", :permerror)
  end

  defp evalp(ctx, [{:redirect, [domain], range} | tail]) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-6.1
    # - if redirect domain has no SPF -> permerror
    # - if redirect domain is mailformed -> permerror
    # - otherwise its result is the result for this SPF
    if loop?(ctx, domain) do
      error(
        ctx,
        :loop,
        "loop detected: #{ctx.domain} cannot redirect to #{domain}",
        :permerror
      )
    else
      ctx =
        test(ctx, :eval, :warn, length(tail) > 0, "terms after #{spf_term(ctx, range)}?")
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

  # TERM UNKNOWN -> internal error
  defp evalp(ctx, [term | tail]) do
    log(ctx, :eval, :error, "internal error, eval is missing a handler for #{inspect(term)}")
    |> evalp(tail)
  end
end
