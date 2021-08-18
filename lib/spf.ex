defmodule Spf do
  @moduledoc """
  Functions to get and debug SPF records.
  """
  import NimbleParsec

  alias Spf.DNS
  import Spf.Tokens
  import Spf.Utils
  import Spf.Eval

  def grep(ctx) do
    {ctx, result} = DNS.resolve(ctx, ctx[:domain], :txt)

    case DNS.grep(result, &spf?/1) do
      {:ok, spf} -> Map.put(ctx, :spf, spf)
      {:error, reason} -> Map.put(ctx, :error, reason) |> Map.put(:spf, [])
    end
  end

  def report(ctx) do
    IO.puts("check(#{ctx.domain}, #{ctx.ip}, #{ctx.sender}) -> #{ctx.verdict}")
  end

  defparsec(:tokenize, Spf.Tokens.terms())
  defdelegate parse(context), to: Spf.Parser

  def check(domain, opts \\ []) do
    context(domain, opts)
    |> grep()
    |> parse()
    |> eval()
    |> report()
  end
end
