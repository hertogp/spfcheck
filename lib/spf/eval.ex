defmodule Spf.Eval do
  @moduledoc """
  Functions to evaluate an SPF context
  """

  alias Spf.DNS
  import Spf.Utils

  # Helpers

  defp match(ctx, term, tail) do
    IO.inspect({ctx, term}, label: :eval_match_12)
    # see if current state is a match
    # TODO: add prechecks, such as ctx.num_dnsq <= ctx.max_dnsq etc..
    {_pfx, qlist} = Iptrie.lookup(ctx.ipt, ctx.ip) || {nil, nil}

    if qlist do
      log(ctx, :note, term, "matches #{ctx.ip}")
      |> tick(:num_checks)
      |> Map.put(:verdict, verdict(qlist, ctx.nth))
    else
      log(ctx, :info, term, "no match")
      |> tick(:num_checks)
      |> evalp(tail)
    end
  end

  defp verdict(qualifier) do
    case qualifier do
      ?+ -> "pass"
      ?- -> "fail"
      ?~ -> "softfail"
      ?? -> "neutral"
      q -> "error, unknown qualifier #{inspect(q)}"
    end
  end

  defp verdict(qlist, nth) do
    {{qualifier, _nth}, _} = List.keytake(qlist, nth, 1) || {{:error, nth}, qlist}

    verdict(qualifier)
  end

  defp push(ctx, domain) do
    state = %{
      depth: ctx.depth,
      domain: ctx.domain,
      f_include: ctx.f_include,
      f_redirect: ctx.f_redirect,
      f_all: ctx.f_all,
      nth: ctx.nth,
      macro: ctx.macro,
      ast: ctx.ast,
      spf: ctx.spf
    }

    nth = ctx.cnt

    tick(ctx, :cnt)
    |> tick(:depth)
    |> Map.put(:stack, [state | ctx.stack])
    |> Map.put(:map, Map.merge(ctx.map, %{nth => domain, domain => nth}))
    |> Map.put(:domain, domain)
    |> Map.put(:f_include, true)
    |> Map.put(:f_redirect, false)
    |> Map.put(:f_all, false)
    |> Map.put(:nth, nth)
    |> Map.put(:macro, macros(domain, ctx.ip, ctx.sender))
    |> Map.put(:ast, [])
    |> Map.put(:spf, "")
  end

  defp pop(ctx) do
    case ctx.stack do
      [] ->
        log(ctx, :error, "attempted to pop from empty stack")

      [state | tail] ->
        Map.put(ctx, :stack, tail)
        |> Map.merge(state)
    end
  end

  # ptr - validate names
  defp validated(ctx, {:ptr, [_, domain], _} = term, {:error, reason}),
    do: log(ctx, :error, term, "DNS error for #{domain}: #{inspect(reason)}")

  defp validated(ctx, term, {:ok, rrs}),
    do: Enum.reduce(rrs, ctx, fn name, acc -> validate(name, acc, term) end)

  defp validate(name, ctx, {:ptr, [q, domain], _}) do
    {ctx, dns} = DNS.resolve(ctx, name, ctx.atype)

    case validate?(dns, ctx.ip, name, domain) do
      true -> addip(ctx, [ctx.ip], [32, 128], {q, ctx.nth})
      false -> ctx
    end
  end

  defp validate?({:error, _}, _ip, _name, _domain),
    do: false

  defp validate?({:ok, rrs}, ip, name, domain) do
    IO.inspect(rrs, label: :rrs)
    pfx = Pfx.new(ip)

    if Enum.any?(rrs, fn ip -> Pfx.member?(ip, pfx) end) do
      String.downcase(name)
      |> String.ends_with?(String.downcase(domain))
    else
      false
    end
  end

  defp explain(ctx) do
    Map.put(ctx, :explanation, ", its just not in the cards")
  end

  # API

  def eval(ctx) do
    evalp(ctx, ctx.ast)
    |> explain()
  end

  defp evalp(ctx, [{:a, [q, domain, dual], _range} = term | tail]) do
    addname(ctx, domain, dual, {q, ctx.nth})
    |> match(term, tail)
  end

  defp evalp(ctx, [{:all, [q], _range} = term | tail]) do
    if ctx.f_include do
      evalp(ctx, tail)
    else
      log(ctx, :info, term, "SPF match by #{List.to_string([q])}all")
      |> tick(:num_checks)
      |> Map.put(:verdict, verdict(q))
    end
  end

  defp evalp(ctx, [{:mx, [q, domain, dual], _range} = term | tail]) do
    addmx(ctx, domain, dual, {q, ctx.nth})
    |> match(term, tail)
  end

  defp evalp(ctx, [{ip, [q, pfx], _range} = term | tail]) when ip in [:ip4, :ip6] do
    addip(ctx, [pfx], [32, 128], {q, ctx.nth})
    |> match(term, tail)
  end

  defp evalp(ctx, [{:ptr, _termval, _range} = term | tail]) do
    # Note:
    # 1 lookup DNS ptr record for <ip>
    # 2 for each name returned, lookup their ips
    # 3 keep names where <ip> is amongst ips
    # 4 match any of the names is a (sub)domain of <tgt-name> (see errata)
    {ctx, dns} = DNS.resolve(ctx, Pfx.dns_ptr(ctx.ip), :ptr)

    validated(ctx, term, dns)
    |> match(term, tail)
  end

  defp evalp(ctx, [{:include, [q, domain], _range} = term | tail]) do
    if ctx.map[domain] do
      log(ctx, :error, term, "ignored: seen before")
    else
      ctx =
        log(ctx, :note, term, "recurse")
        |> push(domain)
        |> Spf.grep()
        |> Spf.parse()
        |> eval()

      case ctx.verdict do
        v when v in ["neutral", "fail", "softfail"] ->
          pop(ctx)
          |> log(:info, term, "no match")
          |> evalp(tail)

        "pass" ->
          Map.put(ctx, :verdict, verdict(q))
          |> pop()
          |> log(:info, term, "match")

        v when v in ["none", "permerror"] ->
          Map.put(ctx, :verdict, "permerror") |> log(:info, term, "permerror")

        "temperror" ->
          ctx
      end
    end
  end

  defp evalp(ctx, [{:redirect, [domain], _range} = term | tail]) do
    IO.inspect(domain, label: :eval_redirect)

    if ctx.map[domain] do
      log(ctx, :error, term, "domain seen before")
    else
      nth = ctx.cnt

      test(ctx, :error, term, length(tail) > 0, "terms after redirect?")
      |> log(:note, term, "redirect")
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
      |> Spf.grep()
      |> Spf.parse()
      |> eval()
    end
  end

  defp evalp(ctx, [term | tail]) do
    log(ctx, :error, term, "eval is missing a handler")
    |> evalp(tail)
  end

  defp evalp(ctx, []),
    do: ctx
end
