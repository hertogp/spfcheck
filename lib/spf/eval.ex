defmodule Spf.Eval do
  @moduledoc """
  Functions to evaluate an SPF context
  """

  alias Spf.DNS
  import Spf.Context

  # Helpers

  defp evalmx(ctx, domain, dual, value) do
    {ctx, dns} = DNS.resolve(ctx, domain, :mx)

    case dns do
      {:error, reason} ->
        log(ctx, :dns, :warn, "mx #{domain} - DNS error #{inspect(reason)}")

      {:ok, []} ->
        log(ctx, :dns, :warn, "mx #{domain} - ZERO answers")

      {:ok, rrs} ->
        Enum.map(rrs, fn {_, name} -> name end)
        |> Enum.reduce(ctx, fn name, acc -> evalname(acc, name, dual, value) end)
        |> log(:dns, :debug, "MX #{domain} #{inspect(value)} added")
    end
  end

  defp evalname(ctx, domain, dual, value) do
    {ctx, dns} = DNS.resolve(ctx, domain, ctx.atype)

    case dns do
      {:error, reason} ->
        log(ctx, :eval, :warn, "#{ctx.atype} #{domain} - DNS error #{inspect(reason)}")

      {:ok, []} ->
        log(ctx, :dns, :warn, "#{ctx.atype} #{domain} - ZERO answers")

      {:ok, rrs} ->
        addip(ctx, rrs, dual, value)
    end
  end

  defp explain(ctx) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-6.2
    if ctx.verdict == :fail and ctx.explain do
      {_token, [domain], _range} = ctx.explain
      {ctx, dns} = DNS.resolve(ctx, domain, :txt)
      # dns query for an explain string does not count
      ctx = tick(ctx, :num_dnsq, -1)

      case dns do
        {:error, reason} ->
          log(ctx, :dns, :warn, "txt #{domain} - DNS error #{reason}")

        {:ok, []} ->
          log(ctx, :dns, :warn, "txt #{domain}i - DNS void lookup (0 answers)")

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
      {:error, _, _, _, _, _} -> ""
      {:ok, [{:exp_str, tokens, _range}], _, _, _, _} -> expand(ctx, tokens)
    end
  end

  defp expand(ctx, {:domain_spec, _, _} = spec),
    do: Spf.Parser.domain(ctx, spec)

  defp expand(_ctx, {:whitespace, [str], _}),
    do: str

  defp expand(_ctx, {:unknown, [str], _}),
    do: str

  defp expand(ctx, tokens) when is_list(tokens) do
    for token <- tokens do
      expand(ctx, token)
    end
    |> Enum.join()
  end

  defp check_limits(ctx) do
    if ctx.nth == 0 do
      ctx =
        if ctx.num_dnsm > ctx.max_dnsm,
          do: log(ctx, :eval, :warn, "Too many DNS mechanisms used (#{ctx.num_dnsm})"),
          else: ctx

      ctx =
        if ctx.num_dnsq > ctx.max_dnsq,
          do: log(ctx, :eval, :warn, "Too many DNS queries issued (#{ctx.num_dnsq})"),
          else: ctx

      if ctx.num_dnsv > ctx.max_dnsv,
        do: log(ctx, :eval, :warn, "Too many VOID DNS queries seen (#{ctx.num_dnsv})"),
        else: ctx
    else
      ctx
    end
  end

  defp match(ctx, {_m, _token, range} = _term, tail) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-4.6.2
    # see if ctx's current state is a match (i.e. <ip> is a match now)
    # TODO:
    # - add prechecks, such as ctx.num_dnsq <= ctx.max_dnsq etc..
    # - store matching term in ctx as :matched_term {term, ctx.nth}
    {_pfx, qlist} = Iptrie.lookup(ctx.ipt, ctx.ip) || {nil, nil}

    if qlist do
      log(ctx, :eval, :note, "#{String.slice(ctx.spf, range)} - matches #{ctx.ip}")
      |> tick(:num_checks)
      |> Map.put(:verdict, verdict(qlist, ctx.nth))
      |> Map.put(:reason, "spf[#{ctx.nth}] #{String.slice(ctx.spf, range)}")
    else
      log(ctx, :eval, :info, "#{String.slice(ctx.spf, range)} - no match")
      |> tick(:num_checks)
      |> evalp(tail)
    end
  end

  # https://www.rfc-editor.org/rfc/rfc7208.html#section-5.5
  # ptr - mechanism
  # 1. resolve PTR RR for <ip> -> names
  # 2. resolve names -> their ip's
  # 3. keep names that have <ip> among their ip's
  # 4. add <ip> if such a (validated) name is (sub)domain of <domain>
  defp validated(ctx, {:ptr, [_, domain], _} = _term, {:error, reason}),
    do: log(ctx, :eval, :warn, "DNS error for #{domain}: #{inspect(reason)}")

  defp validated(ctx, term, {:ok, rrs}),
    do: Enum.reduce(rrs, ctx, fn name, acc -> validate(name, acc, term) end)

  defp validate(name, ctx, {:ptr, [q, domain], _} = term) do
    {ctx, dns} = DNS.resolve(ctx, name, ctx.atype)

    case validate?(dns, ctx.ip, name, domain) do
      true ->
        addip(ctx, [ctx.ip], [32, 128], {q, ctx.nth, term})
        |> log(:eval, :info, "validated: #{name}, #{ctx.ip} for #{domain}")

      false ->
        log(ctx, :eval, :info, "not validated: #{name}, #{ctx.ip} for #{domain}")
    end
  end

  # validate name has an ip == <ip> and is (sub)domain of domain
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

  defp verdict(qualifier) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-4.6.2
    case qualifier do
      ?+ -> :pass
      ?- -> :fail
      ?~ -> :softfail
      ?? -> :neutral
      _ -> :qualifier_error
    end
  end

  defp verdict(qlist, nth) do
    {{qualifier, _nth, _term}, _} = List.keytake(qlist, nth, 1) || {{:error, nth, nil}, qlist}

    verdict(qualifier)
  end

  # API

  def eval(ctx) do
    evalp(ctx, ctx.ast)
    |> explain()
    |> Map.put(:duration, (DateTime.utc_now() |> DateTime.to_unix()) - ctx.macro[?t])
    |> check_limits()
  end

  # HELPERS

  # A
  # TODO: check if we've seen {domain, dual} before
  defp evalp(ctx, [{:a, [q, domain, dual], _range} = term | tail]) do
    evalname(ctx, domain, dual, {q, ctx.nth, term})
    |> match(term, tail)
  end

  # EXISTS
  # https://www.rfc-editor.org/rfc/rfc7208.html#section-5.7
  defp evalp(ctx, [{:exists, [q, domain], _range} = term | tail]) do
    if ctx.map[domain] do
      log(ctx, :eval, :warn, "domain '#{domain}' seen before")
    else
      {ctx, dns} = DNS.resolve(ctx, domain, :a)

      ctx =
        case dns do
          {:error, reason} ->
            log(ctx, :eval, :info, "DNS error #{domain} #{reason}")

          {:ok, rrs} ->
            log(ctx, :eval, :info, "DNS #{inspect(rrs)}")
            |> addip(ctx.ip, [32, 128], {q, ctx.nth, term})
        end

      match(ctx, term, tail)
    end
  end

  # All
  defp evalp(ctx, [{:all, [q], _range} = term | tail]) do
    if ctx.f_include do
      evalp(ctx, tail)
    else
      log(ctx, :eval, :info, "SPF match by #{List.to_string([q])}all")
      |> tick(:num_checks)
      |> addip(ctx.ip, [32, 128], {q, ctx.nth, term})
      |> match(term, tail)
    end
  end

  # MX
  # TODO: check if we've seen {domain, dual} before
  defp evalp(ctx, [{:mx, [q, domain, dual], _range} = term | tail]) do
    evalmx(ctx, domain, dual, {q, ctx.nth, term})
    |> match(term, tail)
  end

  # IP4/6
  defp evalp(ctx, [{ip, [q, pfx], _range} = term | tail]) when ip in [:ip4, :ip6] do
    addip(ctx, [pfx], [32, 128], {q, ctx.nth, term})
    |> match(term, tail)
  end

  # PTR
  # TODO: check is we've seen domain before
  defp evalp(ctx, [{:ptr, [_q, _domain], _range} = term | tail]) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-5.5
    # - see also Errata, 
    {ctx, dns} = DNS.resolve(ctx, Pfx.dns_ptr(ctx.ip), :ptr)

    validated(ctx, term, dns)
    |> match(term, tail)
  end

  # INCLUDE
  defp evalp(ctx, [{:include, [q, domain], range} = _term | tail]) do
    if ctx.map[domain] do
      log(ctx, :eval, :warn, "ignoring included '#{domain}', seen before")
      |> evalp(tail)
    else
      ctx =
        log(ctx, :eval, :note, "#{String.slice(ctx.spf, range)} - recurse")
        |> push(domain)
        |> Spf.grep()
        |> Spf.parse()
        |> eval()

      case ctx.verdict do
        v when v in [:neutral, :fail, :softfail] ->
          ctx = pop(ctx)

          log(ctx, :eval, :info, "#{String.slice(ctx.spf, range)} - no match")
          |> evalp(tail)

        :pass ->
          ctx = pop(ctx)

          ctx
          |> Map.put(:verdict, verdict(q))
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

  # REDIRECT
  defp evalp(ctx, [{:redirect, [domain], _range} = term | tail]) do
    if ctx.map[domain] do
      log(ctx, :eval, :warn, "ignoring redirect '#{domain}', domain seen before")
    else
      nth = ctx.cnt

      test(ctx, :error, term, length(tail) > 0, "terms after redirect?")
      |> log(:eval, :note, "redirecting to #{domain}")
      |> tick(:cnt)
      |> Map.put(:map, Map.merge(ctx.map, %{nth => domain, domain => nth}))
      |> Map.put(:domain, domain)
      |> Map.put(:f_include, false)
      |> Map.put(:f_redirect, false)
      |> Map.put(:f_all, false)
      |> Map.put(:nth, nth)
      |> Map.put(:macro, macros(domain, ctx.ip, ctx.sender))
      |> Map.put(:ast, [])
      |> Map.put(:spf, "")
      |> Map.put(:explain, nil)
      |> Spf.grep()
      |> Spf.parse()
      |> eval()
    end
  end

  # TERM?
  defp evalp(ctx, [term | tail]) do
    log(ctx, :eval, :error, "internal error, eval is missing a handler for #{inspect(term)}")
    |> evalp(tail)
  end

  # NO AST due to no SPF
  defp evalp(ctx, []),
    do: ctx
end
