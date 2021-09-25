defmodule Spf do
  @moduledoc """
  Functions to get and debug SPF records.
  """

  import NimbleParsec

  # Helpers

  @doc """
  Returns true if `str` looks like an SPF record, false otherwise.

  """
  @spec spf?(binary) :: boolean
  def spf?(str) when is_binary(str) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-4.5
    # - we're a bit more relaxed
    str
    |> String.downcase()
    |> String.replace(~r/^\s*/, "")
    |> String.starts_with?("v=spf1")
  end

  def spf?(_),
    do: false

  def grep(ctx) when is_map(ctx) do
    {ctx, result} = Spf.DNS.resolve(ctx, ctx.domain, :txt)

    ctx =
      case Spf.DNS.grep(result, &spf?/1) do
        {:ok, spf} ->
          Map.put(ctx, :spf, spf)

        {:error, reason} ->
          Map.put(ctx, :error, reason)
          |> Map.put(:spf, [])
      end

    ctx
    |> Spf.Context.log(:spf, :note, "SPF (#{ctx.nth}): #{inspect(ctx.spf)}")
  end

  defparsec(:tokenize, Spf.Tokens.tokenize())
  defparsec(:exp_tokens, Spf.Tokens.exp_str())

  def check(sender, opts \\ []) do
    ctx = Spf.Context.new(sender, opts)

    ctx
    |> Spf.Context.log(:spf, :note, "spfcheck(#{ctx.domain}, #{ctx.ip}, #{ctx.sender})")
    |> grep()
    |> Spf.Context.tick(:num_dnsq, -1)
    |> Spf.Parser.parse()
    |> Spf.Eval.eval()
  end
end
