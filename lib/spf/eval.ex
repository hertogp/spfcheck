defmodule Spf.Eval do
  @moduledoc """
  Functions to evaluate an SPF context
  """
  alias Spf.DNS
  import Spf.Utils

  defp match(ctx, term) do
    # see if current state is a match
    {pfx, qd} = Iptrie.lookup(ctx.ipt, ctx.ip) || {nil, nil}

    if qd do
      ctx =
        log(ctx, :info, term, "SPF match by #{pfx}")
        |> Map.put(:verdict, verdict(qd, ctx.num_spf))

      {:match, ctx}
    else
      :no_match
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
    {ctx, ip} = DNS.resolve(ctx, domain, ctx[:atype])

    ctx =
      case ip do
        {:ok, rrs} -> addip(ctx, rrs, dual, {q, ctx[:num_spf]})
        {:error, reason} -> log(ctx, :warn, term, "DNS error #{inspect(reason)}")
      end

    case match(ctx, term) do
      :no_match -> evalp(ctx, tail)
      {:match, ctx} -> ctx
    end
  end

  defp evalp(ctx, [{token, _, _} | tail]) do
    IO.inspect(token, label: :eval_unhandled)
    evalp(ctx, tail)
  end

  defp evalp(ctx, []),
    do: ctx
end
