defmodule Spf do
  @moduledoc """
  Functions to get and debug SPF records.
  """
  import NimbleParsec

  alias Spf.DNS
  alias Spf.Context
  alias Spf.Eval
  alias Spf.Parser

  # Helpers
  # check if string contains v=spf, even if malformed
  @spec spf?(binary) :: boolean
  defp spf?(str) when is_binary(str) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-4.5
    # - we're a bit more relaxed
    str
    |> String.downcase()
    |> String.replace([" ", "\t", "\n", "\r"], "")
    |> String.contains?("v=spf1")
  end

  defp spf?(_),
    do: false

  def grep(ctx) when is_map(ctx) do
    {ctx, result} = DNS.resolve(ctx, ctx[:domain], :txt)

    case DNS.grep(result, &spf?/1) do
      {:ok, spf} -> Map.put(ctx, :spf, spf)
      {:error, reason} -> Map.put(ctx, :error, reason) |> Map.put(:spf, [])
    end
  end

  def grep(domain) when is_binary(domain) do
    ctx = %{dns_timeout: 10000, dns: %{}, domain: domain}
    {_ctx, result} = DNS.resolve(ctx, domain, :txt)
    DNS.grep(result, &spf?/1)
  end

  def report(ctx) do
    IO.puts(
      "check(#{ctx.domain}, #{ctx.ip}, #{ctx.sender}) -> #{ctx.verdict} (#{ctx.explanation})"
    )

    ctx
  end

  defparsec(:tokenize, Spf.Tokens.tokenize())
  defparsec(:exp_tokens, Spf.Tokens.exp_str())
  defdelegate parse(context), to: Spf.Parser

  def check(domain, opts \\ []) do
    Context.new(domain, opts)
    |> grep()
    |> Parser.parse()
    |> Eval.eval()
    |> report()
  end
end
