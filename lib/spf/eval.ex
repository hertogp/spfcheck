defmodule Spf.Eval do
  @moduledoc """
  Functions to evaluate an SPF context
  """
  alias Spf.DNS
  import Spf.Utils

  defp match(ctx, term, tail) do
    # see if current state is a match
    {pfx, qlist} = Iptrie.lookup(ctx.ipt, ctx.ip) || {nil, nil}

    if qlist do
      log(ctx, :info, term, "SPF match by #{pfx}")
      |> Map.put(:verdict, verdict(qlist, ctx.num_spf))
    else
      evalp(ctx, tail)
    end
  end

  def verdict(qd, num_spf) do
    {{qualifier, nth}, _} = List.keytake(qd, num_spf, 1) || {{:error, num_spf}, qd}

    case qualifier do
      ?+ -> "pass"
      ?- -> "fail"
      ?~ -> "softfail"
      ?? -> "neutral"
      :error -> "error, num_spf #{nth}"
      q -> "error, unknown qualifier #{inspect(q)}"
    end
  end

  def eval(ctx),
    do: evalp(ctx, ctx[:ast])

  defp evalp(ctx, [{:a, [q, domain, dual], _range} = term | tail]) do
    addname(ctx, domain, dual, {q, ctx.num_spf})
    |> match(term, tail)
  end

  defp evalp(ctx, [{:mx, [q, domain, dual], _range} = term | tail]) do
    addmx(ctx, domain, dual, {q, ctx.num_spf})
    |> match(term, tail)
  end

  defp evalp(ctx, [{ip, [q, pfx], _range} = term | tail]) when ip in [:ip4, :ip6] do
    addip(ctx, [pfx], [32, 128], {q, ctx.num_spf})
    |> match(term, tail)
  end

  defp evalp(ctx, [{:ptr, [q, domain], _range} = term | tail]) do
    # ip -> ptr lookup -> names -> ips -> keep names that match `domain`
    revname = Pfx.dns_ptr(ctx.ip)
    {ctx, dns} = DNS.resolve(ctx, Pfx.dns_ptr(ctx.ip), :ptr)
    IO.inspect(dns)

    case dns do
      {:error, reason} ->
        log(ctx, :error, term, "DNS error for #{revname}: #{inspect(reason)}") |> evalp(tail)

      {:ok, rrs} ->
        validated(ctx, q, domain, rrs) |> match(term, tail)
    end
  end

  defp evalp(ctx, [{token, _, _} | tail]) do
    IO.inspect(token, label: :eval_unhandled)
    evalp(ctx, tail)
  end

  defp evalp(ctx, []),
    do: ctx

  # ptr - validate names
  def validated(ctx, q, domain, names),
    do: Enum.reduce(names, ctx, fn name, acc -> validate(name, acc, q, domain) end)

  def validate(name, ctx, q, domain) do
    {ctx, dns} = DNS.resolve(ctx, name, ctx.atype)

    case validate?(dns, ctx.ip, name, domain) do
      true -> addip(ctx, [ctx.ip], [32, 128], {q, ctx.num_spf})
      false -> ctx
    end
  end

  defp validate?({:error, _}, _ip, _name, _domain),
    do: false

  defp validate?({:ok, rrs}, ip, name, domain) do
    IO.inspect(rrs, label: :rrs)
    pfx = Pfx.new(ip)

    if Enum.any?(rrs, fn ip -> Pfx.member?(ip, pfx) end) do
      String.downcase(name) |> String.ends_with?(String.downcase(domain))
    end
  end
end
