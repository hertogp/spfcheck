defmodule Spfcheck do
  @external_resource "README.md"
  @moduledoc File.read!("README.md")
             |> String.split("<!-- @MODULEDOC -->")
             |> Enum.fetch!(1)

  alias Spf.Context
  alias IO.ANSI

  @options [
    color: :boolean,
    dns: :string,
    helo: :string,
    help: :boolean,
    ip: :string,
    report: :string,
    verbosity: :integer
  ]

  @aliases [
    H: :help,
    c: :color,
    d: :dns,
    h: :helo,
    i: :ip,
    r: :report,
    v: :verbosity
  ]

  @verbosity %{
    :quiet => 0,
    :error => 1,
    :warn => 2,
    :note => 3,
    :info => 4,
    :debug => 5
  }

  @csv_fields [
    :domain,
    :ip,
    :sender,
    :verdict,
    :reason,
    :num_spf,
    :num_dnsm,
    :num_dnsq,
    :num_dnsv,
    :num_checks,
    :num_warn,
    :num_error,
    :duration,
    :explanation
  ]

  # Helpers

  defp color(type, width) do
    padded = String.pad_leading("#{type}", width)

    iodata =
      case type do
        :error -> ANSI.format([:red_background, :white, padded])
        :warn -> ANSI.format([:light_yellow, padded])
        :note -> ANSI.format([:green, padded])
        :debug -> ANSI.format([:light_blue, padded])
        _ -> padded
      end

    IO.iodata_to_binary(iodata)
  end

  # Log callback

  defp log(ctx, facility, severity, msg) do
    if @verbosity[severity] <= ctx.verbosity do
      nth = String.pad_leading("#{ctx.nth}", 2)
      facility = String.pad_trailing("#{facility}", 5)
      severity = color(severity, 5)
      depth = String.duplicate("| ", ctx.depth)
      lead = "[spf #{nth}][#{facility}][#{severity}] #{depth}"
      IO.puts(:stderr, "#{lead}> #{msg}")
    end
  end

  # MAIN

  @doc """
  Check spf for given ip, sender and domain.
  """
  def main(argv) do
    {opts, senders, _invalid} = OptionParser.parse(argv, aliases: @aliases, strict: @options)

    if Keyword.get(opts, :help, false), do: usage()

    if Keyword.get(opts, :color, true),
      do: Application.put_env(:elixir, :ansi_enabled, true),
      else: Application.put_env(:elixir, :ansi_enabled, false)

    opts = Keyword.put(opts, :log, &log/4)

    if [] == senders,
      do: do_stdin(opts)

    # used by report to print meta information only once.
    opts = Keyword.put(opts, :first, List.first(senders))

    for sender <- senders do
      Spf.check(sender, opts)
      |> report(opts)
    end
  end

  defp do_stdin(parsed) do
    IO.puts(Enum.join(@csv_fields, ","))

    IO.stream()
    |> Enum.each(&do_stdin(parsed, String.trim(&1)))
  end

  # skip comments and empty lines
  defp do_stdin(_parsed, "#" <> _comment), do: nil
  defp do_stdin(_parsed, ""), do: nil

  defp do_stdin(opts, line) do
    argv = String.split(line, ~r/\s+/, trim: true)
    {parsed, domains, _invalid} = OptionParser.parse(argv, aliases: @aliases, strict: @options)
    opts = Keyword.merge(opts, parsed)

    for domain <- domains do
      Spf.check(domain, opts)
      |> csv_result()
    end
  end

  defp csv_result(ctx) do
    Enum.map(@csv_fields, fn field -> "#{inspect(ctx[field])}" end)
    |> Enum.join(",")
    |> IO.puts()
  end

  # Report topics
  defp report(ctx, opts) do
    reports = Keyword.get(opts, :report, "") |> String.downcase() |> String.split("", trim: true)

    topics =
      case reports do
        [] -> ["V"]
        ["a", "l", "l"] -> ["v", "s", "e", "w", "p", "d", "a", "t"]
        topics -> topics
      end

    if Keyword.get(opts, :first, nil) == ctx.domain,
      do: topic(ctx, "h")

    for item <- topics, do: topic(ctx, item)
  end

  # Header (meta)
  defp topic(_ctx, "h") do
    meta = """
    ---
    title: SPF report
    author: spfcheck
    date: #{DateTime.utc_now() |> Calendar.strftime("%c")}
    ...
    """

    IO.puts(meta)
  end

  # Verdict
  defp topic(ctx, "V") do
    # print out verdict without markdown
    Enum.map(@csv_fields, fn field -> {"#{field}", "#{ctx[field]}"} end)
    |> Enum.map(fn {k, v} -> {String.pad_trailing(k, 11, " "), v} end)
    |> Enum.map(fn {k, v} -> IO.puts("#{k}: #{v}") end)
  end

  defp topic(ctx, "v") do
    # wrap verdict in markdown
    IO.puts("\n# Verdict #{ctx.domain}\n")
    IO.puts("```")
    topic(ctx, "V")
    IO.puts("```")
  end

  # Spf's
  defp topic(ctx, "s") do
    IO.puts("\n## SPF\n")
    nths = Map.keys(ctx.map) |> Enum.filter(fn x -> is_integer(x) end) |> Enum.sort()

    IO.puts("```")

    for nth <- nths do
      domain = ctx.map[nth]

      spf = Context.get_spf(ctx, domain)
      IO.puts("[#{nth}] #{domain}")
      IO.puts("    #{spf}")
    end

    IO.puts("```")
  end

  # Warnings
  defp topic(ctx, "w") do
    warnings =
      ctx.msg
      |> Enum.filter(fn t -> elem(t, 2) == :warn end)
      |> Enum.reverse()

    IO.puts("\n## Warnings\n")

    case warnings do
      [] ->
        IO.puts("None.")

      msgs ->
        IO.puts("```")

        Enum.map(msgs, fn {nth, facility, severity, msg} ->
          IO.puts("spf [#{nth}] %#{facility}-#{severity}: #{msg}")
        end)

        IO.puts("```")
    end
  end

  # Errors
  defp topic(ctx, "e") do
    errors =
      ctx.msg
      |> Enum.filter(fn t -> elem(t, 2) == :error end)
      |> Enum.reverse()

    IO.puts("\n## Errors\n")

    case errors do
      [] ->
        IO.puts("None.")

      msgs ->
        IO.puts("```")

        Enum.map(msgs, fn {nth, facility, severity, msg} ->
          IO.puts("spf [#{nth}] %#{facility}-#{severity}: #{msg}")
        end)

        IO.puts("```")
    end
  end

  # Prefixes
  defp topic(ctx, "p") do
    IO.puts("\n## Prefixes\n")
    wseen = 5
    wpfx = 35
    indent = "    "

    spfs =
      for n <- 0..ctx.num_spf do
        {n, Context.get_spf(ctx, n)}
      end
      |> Enum.into(%{})

    IO.puts("#{indent} #Seen #{String.pad_trailing("Prefixes", wpfx)} Source(s)")

    for {ip, v} <- Iptrie.to_list(ctx.ipt) do
      seen = String.pad_trailing("#{length(v)}", wseen)
      pfx = "#{ip}" |> String.pad_trailing(wpfx)

      terms =
        for {_q, nth, {_, _, slice}} <- v do
          "spf[#{nth}] " <> String.slice(Map.get(spfs, nth, ""), slice)
        end
        |> Enum.sort()
        |> Enum.join(", ")

      IO.puts("#{indent} #{seen} #{pfx} #{terms}")
    end
  end

  # DNS
  defp topic(ctx, "d") do
    IO.puts("\n## DNS\n")

    IO.puts("```")

    Spf.DNS.to_list(ctx)
    |> Enum.join("\n")
    |> IO.puts()

    IO.puts("```")

    errors = Spf.DNS.to_list(ctx, valid: false)

    if length(errors) > 0 do
      IO.puts("\n## DNS issues\n")
      IO.puts("```")

      Enum.join(errors, "\n")
      |> IO.puts()

      IO.puts("```")
    end
  end

  # AST
  defp topic(ctx, "a") do
    IO.puts("\n## AST\n")

    IO.puts("```")

    ctx.ast
    |> Enum.map(fn x -> inspect(x) end)
    |> Enum.join("\n")
    |> IO.puts()

    IO.puts("```")
    IO.puts("\nexplain: #{inspect(ctx.explain)}")
  end

  # Tokens
  defp topic(ctx, "t") do
    IO.puts("\n## Tokens\n")

    IO.puts("```")

    ctx.spf_tokens
    |> Enum.map(fn x -> inspect(x) end)
    |> Enum.join("\n")
    |> IO.puts()

    IO.puts("```")
  end

  # Unknown Topic
  defp topic(_ctx, ltr),
    do: IO.puts("unknown topic #{ltr} ignored")

  defp usage() do
    IO.puts(@moduledoc)
    exit({:shutdown, 1})
  end
end
