defmodule Spf.Eval do
  @moduledoc """
  Functions to evaluate an SPF context
  """
  alias Spf.DNS
  import Spf.Utils

  def eval(ctx),
    do: evalp(ctx, ctx[:ast])

  defp evalp(ctx, [{:a, [q, domain, dual], _range} = token | tail]) do
    {ctx, ip} = DNS.resolve(ctx, domain, ctx[:atype])

    ctx =
      case ip do
        {:ok, rrs} -> addip(ctx, rrs, dual, {q, ctx[:num_spf]})
        {:error, reason} -> log(ctx, :warn, token, "DNS error #{inspect(reason)}")
      end

    evalp(ctx, tail)
  end

  defp evalp(ctx, [{token, _, _} | tail]) do
    IO.inspect(token, label: :eval_unhandled)
    evalp(ctx, tail)
  end

  defp evalp(ctx, []),
    do: ctx
end
