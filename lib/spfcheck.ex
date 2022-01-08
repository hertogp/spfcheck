defmodule Spfcheck do
  @external_resource "README.md"
  @moduledoc File.read!("README.md")
             |> String.split("<!-- @MODULEDOC -->")
             |> Enum.fetch!(1)

  alias IO.ANSI

  @options [
    author: :string,
    batch: :integer,
    color: :boolean,
    dns: :string,
    helo: :string,
    help: :boolean,
    ip: :string,
    markdown: :boolean,
    nameserver: :keep,
    report: :string,
    timeout: :integer,
    title: :string,
    verbosity: :integer,
    width: :integer
  ]

  @aliases [
    H: :help,
    a: :author,
    b: :batch,
    c: :color,
    d: :dns,
    h: :helo,
    i: :ip,
    m: :markdown,
    n: :nameserver,
    r: :report,
    t: :title,
    T: :timeout,
    v: :verbosity,
    w: :width
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
    :owner,
    :contact,
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

  # MAIN

  @doc """
  Main entry point for `spfcheck` cli command.

  """
  def main(argv) do
    {opts, senders, _invalid} = OptionParser.parse(argv, aliases: @aliases, strict: @options)

    if Keyword.get(opts, :help, false), do: usage()

    if Keyword.get(opts, :color, true),
      do: Application.put_env(:elixir, :ansi_enabled, true),
      else: Application.put_env(:elixir, :ansi_enabled, false)

    opts = Keyword.put(opts, :log, &log/4)

    if senders == [] do
      do_stdin(opts)
    else
      # used by report to print meta information only once.
      opts = Keyword.put(opts, :first, List.first(senders))

      for sender <- senders do
        Spf.check(sender, opts)
        |> report(opts)
      end
    end
  end

  # Helpers

  defp color(msg, type) do
    iodata =
      case type do
        :error -> ANSI.format([:red_background, :white, msg])
        :warn -> ANSI.format([:light_yellow, msg])
        :note -> ANSI.format([:green, msg])
        :debug -> ANSI.format([:light_blue, msg])
        _ -> msg
      end

    IO.iodata_to_binary(iodata)
  end

  defp log(ctx, facility, severity, msg) do
    # log callback
    if @verbosity[severity] <= ctx.verbosity do
      domain = "#{ctx.map[0]}"
      nth = "#{ctx.nth}"
      fac = "#{facility}"
      sev = "#{severity}"
      depth = String.duplicate("| ", ctx.depth)

      lead = String.pad_trailing("%spf[#{nth}]-#{fac}-#{sev}:", 20, " ") |> color(severity)

      IO.puts(:stderr, "#{domain} #{lead}#{depth}> #{msg}")
    end
  end

  defp text_wrap(text, max, joiner) do
    # simple text wrapper to keep lengthy spf records readable
    if String.length(text) > max do
      String.split(text, ~r/\s+/, trim: true)
      |> assemble("", [], max)
      |> Enum.join(joiner)
    else
      text
    end
  end

  defp assemble([], line, lines, _max),
    do: lines ++ [line]

  defp assemble([word | rest], line, lines, max) do
    if String.length(word) + String.length(line) + 1 > max do
      assemble(rest, "#{word}", lines ++ [line], max)
    else
      prev = if line == "", do: "", else: "#{line} "
      assemble(rest, "#{prev}#{word}", lines, max)
    end
  end

  defp do_stdin(opts) do
    IO.puts(Enum.join(@csv_fields, ","))
    batch = Keyword.get(opts, :batch, 0)

    if batch > 0 do
      Task.Supervisor.start_link(name: Spf.TaskSupervisor)
      do_batch(batch, opts)
    else
      IO.stream()
      |> Enum.each(&do_line(opts, String.trim(&1)))
    end
  end

  defp do_batch(0, _opts),
    do: :ok

  defp do_batch(max, opts) do
    batch =
      IO.stream(:stdio, :line)
      |> Enum.take(max)
      |> Enum.map(&String.trim/1)
      |> Enum.map(
        &Task.Supervisor.async_nolink(Spf.TaskSupervisor, fn -> do_line(opts, &1) end,
          shutdown: 20000
        )
      )
      |> Enum.map(fn t -> Task.await(t, :infinity) end)

    max =
      case batch do
        [] -> 0
        _ -> max
      end

    do_batch(max, opts)
  end

  # skip comments and empty lines
  defp do_line(_opts, "#" <> _comment), do: nil
  defp do_line(_opts, ""), do: nil

  defp do_line(opts, line) do
    argv = String.split(line, ~r/\s+/, trim: true)
    {parsed, senders, _invalid} = OptionParser.parse(argv, aliases: @aliases, strict: @options)
    opts = Keyword.merge(opts, parsed)

    for sender <- senders do
      Spf.check(sender, opts)
      |> csv_result()
    end
  end

  @spec csv_result(Spf.Context.t()) :: :ok
  defp csv_result(ctx) do
    # Enum.map(@csv_fields, fn field -> inspect(ctx[field]) end)
    # |> Enum.join(",")
    # |> IO.puts()
    @csv_fields
    |> Enum.map(fn field -> escape_quotes(ctx[field]) end)
    |> Enum.join(",")
    |> IO.puts()
  end

  defp escape_quotes(""),
    do: ""

  defp escape_quotes(str) when is_binary(str),
    do: "\"#{String.replace(str, ~s("), ~s(""))}\""

  defp escape_quotes(arg),
    do: arg

  defp dot_domain(nth, ctx) do
    domain = ctx.map[nth]
    spf = ctx.map[domain]

    # note: copy over dns + macro related fields of the original
    # maybe keep a map of nth -> ast instead of reparsing, but then again
    # how often will a graph be reported?
    Spf.Context.new(domain)
    |> Map.put(:spf, spf)
    |> Map.put(:dns, ctx.dns)
    |> Map.put(:ip, ctx.ip)
    |> Map.put(:sender, ctx.sender)
    |> Map.put(:helo, ctx.helo)
    |> Map.put(:local, ctx.local)
    |> Spf.Parser.parse()
    |> dot_domain_defs(ctx)
  end

  defp dot_domain_defs(%{:spf => ""} = new, ctx) do
    # an include/redirect to a non-existing spf record
    color = "red"

    nths =
      Map.keys(ctx.map)
      |> Enum.filter(fn n -> ctx.map[n] == new.domain end)
      |> Enum.join("][")

    {_, contact} =
      case Spf.DNS.authority(ctx, new.domain) do
        {:ok, _, owner, email} -> {owner, email}
        {:error, reason} -> {"DNS error", "#{reason}"}
      end

    """
    "#{new.domain}" [label=<
      <TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0">
      <TR><TD PORT="TOP" BGCOLOR="#{color}">[#{nths}] #{new.domain}</TD></TR>
      <TR><TD BGCOLOR="lightgray">#{contact}</TD></TR>
      <TR><TD>NO SPF</TD></TR>
      </TABLE>
      >, shape="plaintext"];
    """
  end

  defp dot_domain_defs(new, ctx) do
    nths = Map.keys(ctx.map) |> Enum.filter(fn n -> ctx.map[n] == new.domain end)
    errs = Enum.filter(ctx.msg, fn {n, _, s, _} -> n in nths and s == :error end) |> length()
    warn = Enum.filter(ctx.msg, fn {n, _, s, _} -> n in nths and s == :warn end) |> length()
    nths = Enum.join(nths, "][")

    color =
      cond do
        errs > 0 -> "red"
        warn > 0 -> "yellow"
        true -> "green"
      end

    errs = if errs > 0, do: "<TR><TD>#{errs} errors</TD></TR>", else: ""
    warn = if warn > 0, do: "<TR><TD>#{warn} warnings</TD></TR>", else: ""

    entries =
      new.ast
      |> Enum.map(fn {type, args, range} ->
        {new.domain, type, args, String.slice(new.spf, range)}
      end)
      |> Enum.with_index(&dot_node_entry/2)

    rows = Enum.map(entries, fn {row, _vtx} -> row end)
    vert = Enum.map(entries, fn {_row, vtx} -> vtx end) |> Enum.filter(fn v -> v != "" end)

    {_, contact} =
      case Spf.DNS.authority(ctx, new.domain) do
        {:ok, _, owner, email} -> {owner, email}
        {:error, reason} -> {"DNS error", "#{reason}"}
      end

    """
    "#{new.domain}" [label=<
      <TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0">
      <TR><TD PORT="TOP" BGCOLOR="#{color}">[#{nths}] #{new.domain}</TD></TR>
      <TR><TD BGCOLOR="lightgray">#{contact}</TD></TR>
      #{Enum.join(rows, "\n  ")}
      #{warn}
      #{errs}
      </TABLE>
      >, shape="plaintext"];

      #{Enum.join(vert, "\n  ")}
    """
  end

  # return a table row definition + vertice if applicable
  # - only include/redirect will point to another SPF record
  # - row uses spf term as found in input string
  # - vertex uses expanded term to point to another record
  defp dot_node_entry({domain, :include, args, term}, idx) do
    name = List.last(args)

    row = "<TR><TD PORT=\"#{idx}\">#{term}</TD></TR>"
    vtx = "\"#{domain}\":\"#{idx}\" -> \"#{name}\":\"TOP\";"
    {row, vtx}
  end

  defp dot_node_entry({domain, :redirect, args, term}, idx) do
    name = List.last(args)

    row = "<TR><TD PORT=\"#{idx}\">#{term}</TD></TR>"
    vtx = "\"#{domain}\":\"#{idx}\" -> \"#{name}\":\"TOP\";"
    {row, vtx}
  end

  defp dot_node_entry({_domain, _type, _args, term}, _idx) do
    row = "<TR><TD>#{term}</TD></TR>"
    {row, ""}
  end

  # Report topics

  defp report(ctx, opts) do
    report = Keyword.get(opts, :report, "") |> String.downcase() |> String.split("", trim: true)
    width = Keyword.get(opts, :width, 60)

    topics =
      case report do
        [] -> ["v"]
        ["a", "l", "l"] -> ["v", "g", "s", "e", "w", "p", "d", "a", "t"]
        topics -> topics
      end

    markdown =
      (length(topics) > 1 and Keyword.get(opts, :markdown, true)) or
        (length(topics) == 1 and Keyword.get(opts, :markdown, false))

    if Keyword.get(opts, :first, nil) == ctx.domain,
      do: meta_data(ctx, markdown, opts)

    if markdown,
      do: IO.puts("\n# #{ctx.domain}"),
      else: IO.puts("")

    ctx = Map.put(ctx, :log, nil)

    for item <- topics, do: topic(ctx, item, markdown, width)
  end

  # Header (meta)
  defp meta_data(_ctx, markdown, opts) do
    if markdown do
      meta = """
      ---
      title: #{Keyword.get(opts, :title, "SPF report")}
      author: #{Keyword.get(opts, :author, "spfcheck")}
      date: #{DateTime.utc_now() |> Calendar.strftime("%c")}
      ...
      """

      IO.puts(meta)
    end
  end

  # Verdict
  defp topic(ctx, "v", markdown, width) do
    # wrap verdict in markdown
    if markdown, do: IO.puts("\n## Verdict\n\n```")

    Enum.map(@csv_fields, fn field -> {"#{field}", "#{ctx[field]}"} end)
    |> Enum.map(fn {k, v} -> {String.pad_trailing(k, 11, " "), v} end)
    |> Enum.map(fn {k, v} -> "#{k}: #{v}" end)
    |> Enum.map(&text_wrap(&1, width, "\n             "))
    |> Enum.join("\n")
    |> IO.puts()

    if markdown, do: IO.puts("```"), else: IO.puts("")
  end

  # Spf's
  defp topic(ctx, "s", markdown, width) do
    if markdown, do: IO.puts("\n## SPF\n\n```")
    # donot log DNS stuff to console
    ctx = Map.put(ctx, :verbosity, 0)

    for nth <- 0..(ctx.num_spf - 1) do
      domain = ctx.map[nth]

      {owner, email} =
        case Spf.DNS.authority(ctx, domain) do
          {:ok, _, owner, email} -> {owner, email}
          {:error, reason} -> {"DNS error", "#{reason}"}
        end

      spf = ctx.map[domain] |> text_wrap(width, "\n    ")
      spf = if String.length(spf) < 1, do: "No SPF found", else: spf
      IO.puts("[#{nth}] #{domain} -- (#{owner}, #{email})")
      IO.puts("    #{spf}\n")
    end

    if markdown, do: IO.puts("```"), else: IO.puts("")
  end

  # Warnings
  defp topic(ctx, "w", markdown, _width) do
    warnings =
      ctx.msg
      |> Enum.filter(fn t -> elem(t, 2) == :warn end)
      |> Enum.reverse()

    if markdown, do: IO.puts("\n## Warnings\n\n```")

    case warnings do
      [] ->
        IO.puts("No warnings.")

      msgs ->
        Enum.map(msgs, fn {nth, facility, severity, msg} ->
          IO.puts("%spf[#{nth}]-#{facility}-#{severity}: #{msg}")
        end)
    end

    if markdown, do: IO.puts("```"), else: IO.puts("")
  end

  # Errors
  defp topic(ctx, "e", markdown, _width) do
    errors =
      ctx.msg
      |> Enum.filter(fn t -> elem(t, 2) == :error end)
      |> Enum.reverse()

    if markdown, do: IO.puts("\n## Errors\n\n```")

    case errors do
      [] ->
        IO.puts("No errors.")

      msgs ->
        Enum.map(msgs, fn {nth, facility, severity, msg} ->
          IO.puts("%spf[#{nth}]-#{facility}-#{severity}: #{msg}")
        end)
    end

    if markdown, do: IO.puts("```"), else: IO.puts("")
  end

  # Prefixes
  defp topic(ctx, "p", markdown, _width) do
    if markdown, do: IO.puts("\n## Prefixes\n\n```")
    wseen = 2
    width = 39

    IO.puts("#  #{String.pad_trailing("Prefixes", width)} Source(s)")

    for {ip, v} <- Iptrie.to_list(ctx.ipt) do
      seen = String.pad_trailing("#{length(v)}", wseen)
      pfx = "#{ip}" |> String.pad_trailing(width)

      terms =
        for {_q, _nth, donor} <- v do
          donor
        end
        |> Enum.sort()
        |> Enum.join(", ")

      IO.puts("#{seen} #{pfx} #{terms}")
    end

    if markdown, do: IO.puts("```"), else: IO.puts("")
  end

  # DNS
  defp topic(ctx, "d", markdown, width) do
    if markdown, do: IO.puts("\n## DNS\n\n```")

    Spf.DNS.to_list(ctx)
    |> Enum.map(fn rr -> text_wrap(rr, width, "\n    ") end)
    |> Enum.join("\n")
    |> IO.puts()

    if markdown, do: IO.puts("```")

    issues = Spf.DNS.to_list(ctx, valid: false)

    if length(issues) > 0 do
      if markdown, do: IO.puts("\n## DNS issues\n\n```")

      issues
      |> Enum.map(fn rr -> text_wrap(rr, width, "\n   ") end)
      |> Enum.join("\n")
      |> IO.puts()

      if markdown, do: IO.puts("```"), else: IO.puts("")
    end
  end

  # Graphviz
  defp topic(ctx, "g", markdown, _width) do
    if markdown, do: IO.puts("\n## Graphviz\n\n```graphviz")

    gdefs = for nth <- 0..(ctx.num_spf - 1), do: dot_domain(nth, ctx)

    # use 0-th domain, not ctx.domain (which might be a redirected domain)
    label =
      "spfcheck(#{ctx.local}@#{ctx.map[0]}, #{ctx.ip})" <>
        " -> #{ctx.verdict},  reason #{ctx.reason}" <>
        "\n#{ctx.explanation}"

    digraph = """
    digraph SPF {
      label="#{label}";
      labelloc="t";
      rankdir="LR";
      ranksep="1.0 equally";

      #{Enum.join(gdefs, "\n\n")}

      }
    """

    IO.puts(digraph)

    if markdown, do: IO.puts("```")
  end

  # AST
  defp topic(ctx, "a", markdown, _width) do
    if markdown, do: IO.puts("\n## AST\n\n```")

    ctx.ast
    |> Enum.map(fn x -> inspect(x) end)
    |> Enum.join("\n")
    |> IO.puts()

    if markdown, do: IO.puts("```")
    IO.puts("\nexplain: #{inspect(ctx.explain)}")
  end

  # Tokens
  defp topic(ctx, "t", markdown, _width) do
    if markdown, do: IO.puts("\n## Tokens\n\n```")

    ctx.spf_tokens
    |> Enum.map(fn x -> inspect(x) end)
    |> Enum.join("\n")
    |> IO.puts()

    if markdown, do: IO.puts("```"), else: IO.puts("")
  end

  # Unknown Topic
  defp topic(_ctx, ltr, _markdown, _width),
    do: IO.puts("unknown topic #{ltr} ignored")

  defp usage() do
    IO.puts(@moduledoc)
    exit({:shutdown, 1})
  end
end
