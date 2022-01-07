defmodule Spf.Eval do
  @moduledoc """
  Functions to evaluate an SPF context.

  """

  alias Spf.DNS
  import Spf.Context

  @type dns_result :: Spf.DNS.dns_result()

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

  # def spf?(_),
  #   do: false

  @doc """
  Given a [`context`](`t:Spf.Context.t/0`) retrieve and evaluate the associated SPF record.

  After an (attempted) evaluation, returns an updated context where:
  - `:verdict` is an `t:Spf.Context.verdict/0`
  - `:reason` shows the SPF term responsible for the verdict
  - `:explanation` is the expanded explain-string (if possible and applicable)
  - `:error` shows what (last) error was seen (if any)
  - `:ipt` which maps the prefixes seen during evaluation to their source
  - `:msg` which lists log messages accumulated during evaluation

  and other fields containing information gathered during the evaluation.

  The context is passed around accumulating information and tracks the state of
  the evaluation. Its `:log` is either `nil` or points to a `log/4`-function
  that then called with the `context`, `facility`, `severity` and a `message`
  so it can dump it to screen or somewhere else.

  """
  @spec evaluate(Spf.Context.t()) :: Spf.Context.t()
  def evaluate(ctx) do
    ctx
    |> check_domain()
    |> grep_spf()
    |> Spf.Parser.parse()
    |> eval()
  end

  @doc """
  Returns true if `name` is a validated name for given `domain`.

  The [`dns_result`](`t:dns_result/0`) should contain the ip addresses
  associated with given `name`. If any of the ip adresss match the given `ip`,
  the `name` is a validated domain name for given `domain`.

  If the `exact` flag is true, then the `name` is also required to
  end with given `domain` as well.

  Note that when trying to validate names during the expansion of the p-macro,
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

  @spec evalname(Spf.Context.t(), binary, list, any) :: Spf.Context.t()
  defp evalname(ctx, domain, dual, value) do
    {ctx, dns} = DNS.resolve(ctx, domain, type: ctx.atype)

    case dns do
      {:error, reason} ->
        log(ctx, :eval, :warn, "#{ctx.atype} #{domain} - DNS error #{inspect(reason)}")

      {:ok, rrs} ->
        addip(ctx, rrs, dual, value)
    end
  end

  @spec explain(Spf.Context.t()) :: Spf.Context.t()
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

  @spec check_limits(Spf.Context.t()) :: Spf.Context.t()
  defp check_limits(ctx) do
    # only check for original SPF record, so we donot prematurely stop processing
    if ctx.nth == 0 do
      ctx =
        if ctx.num_dnsm > ctx.max_dnsm do
          error(
            ctx,
            :eval,
            :too_many_dnsm,
            "too many DNS mechanisms used (#{ctx.num_dnsm})",
            :permerror
          )
        else
          ctx
        end

      if ctx.num_dnsv > ctx.max_dnsv do
        error(
          ctx,
          :eval,
          :too_many_dnsv,
          "too many VOID DNS queries seen (#{ctx.num_dnsv})",
          :permerror
        )
      else
        ctx
      end
    else
      ctx
    end
  end

  @spec match(Spf.Context.t(), tuple, list) :: Spf.Context.t()
  defp match(%{error: error} = ctx, _term, _tail) when error != nil,
    # a fatal error was already recorded, so bailout
    do: ctx

  defp match(ctx, {_q, _token, range} = _term, tail) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-4.6.2

    term = spf_term(ctx, range)
    verdict = verdict(ctx)

    if verdict do
      # ctx.ip has a match, so set corresponding result and we're done
      log(ctx, :eval, :note, "#{term} - matches #{ctx.ip}")
      |> tick(:num_checks)
      |> Map.put(:verdict, verdict)
      |> Map.put(:reason, "#{term}")
    else
      # no match, so continue evaluation
      log(ctx, :eval, :info, "#{term} - no match")
      |> tick(:num_checks)
      |> evalp(tail)
    end
  end

  @spec validate(binary, Spf.Context.t(), tuple) :: Spf.Context.t()
  defp validate(name, ctx, {:ptr, [q, domain], range}) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-5.5
    {ctx, dns} = DNS.resolve(ctx, name, type: ctx.atype)
    term = spf_term(ctx, range)

    case validate?(dns, ctx.ip, name, domain, true) do
      true ->
        addip(ctx, [ctx.ip], [32, 128], {q, ctx.nth, term})
        |> log(:eval, :info, "#{term} - validated #{name} (#{ctx.ip}) for #{domain}")

      false ->
        log(ctx, :eval, :info, "#{term} - didn't validate #{name} (#{ctx.ip}) for #{domain}")
    end
  end

  @spec verdict(Spf.Context.t()) :: nil | atom
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

  @spec check_domain(Spf.Context.t()) :: Spf.Context.t()
  defp check_domain(ctx) do
    # as a first action of evaluate(ctx), check the domain:
    # - if not a legal fqdn -> evaluation result is :none
    case Spf.DNS.check_domain(ctx.domain) do
      {:ok, _domain} ->
        ctx

      {:error, reason} ->
        error(ctx, :eval, :illegal_domain, "domain error (#{reason})", :none)
    end
  end

  @spec grep_spf(Spf.Context.t()) :: Spf.Context.t()
  defp grep_spf(ctx) do
    # either set ctx.spf to an SPF record, or set ctx.error to some atom error
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-4.3
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-4.4
    # *temperror* for:
    # - servfail (RCODE 2)
    # - some error (where RCODE !=0 (NOERROR) and RCODE!=3 (NXDOMAIN)), or
    # - timeout
    # *none* for:
    # - nxdomain
    # - zero_answers
    # - malformed domain
    {ctx, result} = Spf.DNS.resolve(ctx, ctx.domain, type: :txt, stats: false)

    case Spf.DNS.filter(result, &spf?/1) do
      {:ok, []} ->
        error(ctx, :eval, :no_spf, "no SPF record found", :none)

      {:ok, [spf]} ->
        if ascii?(spf),
          do: Map.put(ctx, :spf, spf),
          else: error(ctx, :eval, :non_ascii_spf, "SPF contains non-ascii characters", :permerror)

      {:ok, list} ->
        error(
          ctx,
          :eval,
          :too_many_spf,
          "too many SPF records found (#{length(list)})",
          :permerror
        )

      {:error, :nxdomain} ->
        error(ctx, :eval, :nxdomain, "txt #{ctx.domain} - DNS error (nxdomain)", :none)

      {:error, :zero_answers} ->
        error(ctx, :eval, :zero_answers, "txt #{ctx.domain} - DNS error (zero answers)", :none)

      {:error, :illegal_name} ->
        error(ctx, :eval, :illegal_name, "txt #{ctx.domain} - DNS error (illegal name)", :none)

      {:error, :timeout} ->
        error(ctx, :eval, :timeout, "txt #{ctx.domain} - DNS error (timeout)", :temperror)

      {:error, :servfail} ->
        error(ctx, :eval, :servfail, "txt #{ctx.domain} - DNS error (servfail)", :temperror)

      {:error, reason} ->
        error(ctx, :eval, :dns_error, "txt #{ctx.domain} - DNS error (#{reason})", :temperror)
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
    |> then(
      &log(
        &1,
        :eval,
        :note,
        "spf[#{&1.nth}] #{&1.domain} - verdict #{&1.verdict}, reason #{&1.reason}"
      )
    )
  end

  @spec evalp(Spf.Context.t(), list) :: Spf.Context.t()
  defp evalp(ctx, []),
    # Nomore Terms
    do: ctx

  # A
  defp evalp(ctx, [{:a, [q, domain, dual], range} = term | tail]) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-5.3
    {ctx, dns} = DNS.resolve(ctx, domain, type: ctx.atype)
    spfterm = spf_term(ctx, range)

    case dns do
      {:error, reason} when reason in [:nxdomain, :zero_answers, :illegal_name] ->
        ctx

      {:error, reason} ->
        error(ctx, :eval, reason, "#{spfterm} - #{reason}", :temperror)

      {:ok, rrs} ->
        addip(ctx, rrs, dual, {q, ctx.nth, spfterm})
    end
    |> match(term, tail)
  end

  # All
  defp evalp(ctx, [{:all, [q], range} = _term | _tail]) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-5.1
    term = spf_term(ctx, range)

    log(ctx, :eval, :note, "#{term} - matches")
    |> tick(:num_checks)
    |> Map.put(:verdict, qualify(q))
    |> Map.put(:reason, "#{term}")
  end

  # EXISTS
  defp evalp(ctx, [{:exists, [q, domain], range} = term | tail]) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-5.7
    {ctx, dns} = DNS.resolve(ctx, domain, type: :a)
    spfterm = spf_term(ctx, range)
    spfsame? = ctx.domain == String.downcase(domain)

    case dns do
      {:error, reason} when reason in [:nxdomain, :zero_answers, :illegal_name] ->
        ctx

      {:error, reason} ->
        error(ctx, :eval, reason, "#{spfterm} - #{reason}", :temperror)

      {:ok, rrs} ->
        log(ctx, :eval, :info, "#{spfterm} - got DNS #{inspect(rrs)}")
        |> addip(ctx.ip, [32, 128], {q, ctx.nth, spfterm})
        |> test(:eval, :warn, spfsame?, "#{spfterm} - same as main SPF domain (#{ctx.domain})")
    end
    |> match(term, tail)
  end

  # INCLUDE
  defp evalp(ctx, [{:include, [q, domain], range} = _term | tail]) do
    term = spf_term(ctx, range)

    if loop?(ctx, domain) do
      # https://www.rfc-editor.org/rfc/rfc7208.html#section-4.6.4
      # testsuite 14.2 include-loop
      error(
        ctx,
        :eval,
        :loop,
        "#{term} - loop: #{ctx.domain} cannot include #{domain}",
        :permerror
      )
    else
      ctx =
        log(ctx, :eval, :note, "#{term} - recurse")
        |> push(domain)
        |> evaluate()

      # https://www.rfc-editor.org/rfc/rfc7208.html#section-5.2
      case ctx.verdict do
        v when v in [:neutral, :fail, :softfail] ->
          pop(ctx)
          |> log(:eval, :note, "#{term} - no match")
          |> evalp(tail)

        :pass ->
          pop(ctx)
          |> Map.put(:verdict, qualify(q))
          |> log(:eval, :note, "#{term} - match")
          |> Map.put(:reason, "#{term} - matched")

        v when v in [:none, :permerror] ->
          pop(ctx)
          |> error(:eval, :include, "#{term} - permanent error", :permerror)

        :temperror ->
          pop(ctx)
          |> error(:eval, :include, "#{term} - temporary error", :temperror)
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
    spfterm = spf_term(ctx, range)

    case dns do
      {:error, reason} when reason in [:nxdomain, :zero_answers, :illegal_name] ->
        ctx

      {:error, reason} ->
        error(ctx, :eval, reason, "#{spfterm} - #{reason}", :temperror)

      {:ok, [{0, "."}]} ->
        # https://www.rfc-editor.org/rfc/rfc7505.html#section-3
        log(ctx, :eval, :warn, "#{spfterm} - unusable due to null MX for #{domain}")

      {:ok, rrs} when length(rrs) > 10 ->
        # https://www.rfc-editor.org/rfc/rfc7208.html#section-4.6.4
        error(ctx, :eval, :too_many_mtas, "#{spfterm} - too many mta's", :permerror)

      {:ok, rrs} ->
        Enum.map(rrs, fn {_pref, name} -> name end)
        |> Enum.take(10)
        |> Enum.reduce(ctx, fn name, acc -> evalname(acc, name, dual, {q, ctx.nth, spfterm}) end)
        |> log(:dns, :debug, "MX #{domain} #{inspect({q, ctx.nth, term})} added")
    end
    |> match(term, tail)
  end

  # PTR
  defp evalp(ctx, [{:ptr, [_q, domain], range} = term | tail]) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-5.5
    # https://www.rfc-editor.org/errata/eid4751
    domain = Spf.DNS.normalize(domain)
    {ctx, dns} = DNS.resolve(ctx, Pfx.dns_ptr(ctx.ip), type: :ptr)
    spfterm = spf_term(ctx, range)

    case dns do
      {:error, reason} when reason in [:nxdomain, :zero_answers, :illegal_name] ->
        ctx

      {:error, reason} ->
        error(ctx, :eval, reason, "#{spfterm} - #{reason}", :temperror)

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
  defp evalp(ctx, [{:redirect, [domain], range} | tail]) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-6.1
    # - if redirect domain has no SPF -> permerror
    # - if redirect domain is mailformed (seen by evaluate())-> permerror
    # - otherwise its result is the result for this SPF
    term = spf_term(ctx, range)
    trailing? = length(tail) > 0

    if loop?(ctx, domain) do
      # https://www.rfc-editor.org/rfc/rfc7208.html#section-4.6.4
      # testsuite 14.8 redirect-loop
      error(
        ctx,
        :eval,
        :loop,
        "#{term} - loop: #{ctx.domain} cannot redirect to #{domain}",
        :permerror
      )
    else
      ctx =
        test(ctx, :eval, :warn, trailing?, "#{term} - has trailing terms")
        |> log(:eval, :note, "#{term} - redirecting to #{domain}")
        |> redirect(domain)
        |> evaluate()

      if ctx.error in [:no_spf, :nxdomain] do
        error(ctx, :eval, :no_redir_spf, "#{term} - no SPF found for #{domain}", :permerror)
      else
        ctx
      end
    end
  end
end
