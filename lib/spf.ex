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

  @doc """
  Returns true if `str` looks like an SPF record, false otherwise.

  """
  @spec spf?(binary) :: boolean
  def spf?(str) when is_binary(str) do
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-4.5
    # - we're a bit more relaxed
    str
    |> String.downcase()
    |> String.replace([" ", "\t", "\n", "\r"], "")
    |> String.contains?("v=spf1")
  end

  def spf?(_),
    do: false

  def grep(ctx) when is_map(ctx) do
    {ctx, result} = DNS.resolve(ctx, ctx.domain, :txt)

    case DNS.grep(result, &spf?/1) do
      {:ok, spf} ->
        Map.put(ctx, :spf, spf)

      {:error, reason} ->
        Map.put(ctx, :error, reason) |> Map.put(:spf, [])
    end
  end

  def grep(domain) when is_binary(domain) do
    ctx = %{dns_timeout: 10000, dns: %{}, domain: domain}
    {_ctx, result} = DNS.resolve(ctx, domain, :txt)
    DNS.grep(result, &spf?/1)
  end

  def report(ctx) do
    tstamp = DateTime.utc_now() |> DateTime.to_unix()
    ctx = Map.put(ctx, :duration, tstamp - ctx.macro[?t])

    case ctx.report do
      :short ->
        {ctx.verdict, ctx.explanation, ctx.match}

      :medium ->
        {ctx.verdict, ctx.explanation, ctx.match, ctx.duration, ctx.num_checks, ctx.num_dnsq,
         ctx.num_dnsv, ctx.dnsm}

      _ ->
        ctx
    end
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

  def debug(domain, opts \\ []) do
    ctx = check(domain, Keyword.put(opts, :report, :ctx))
    IO.inspect(ctx)
    IO.puts("SPF record  : #{ctx.spf}")
    IO.puts("num DNS mech: #{ctx.num_dnsm} / #{ctx.max_dnsm}")
    IO.puts("DNS requests: #{ctx.num_dnsq} / #{ctx.max_dnsq}")
    IO.puts("DNS void req: #{ctx.num_dnsv} / #{ctx.max_dnsv}")
    IO.puts("#checks made: #{ctx.num_checks}")
    IO.puts("verdict     : #{ctx.verdict} (#{ctx.explanation})")
  end
end
