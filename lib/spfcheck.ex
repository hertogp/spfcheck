defmodule Spfcheck do
  @external_resource "README.md"
  @moduledoc File.read!("README.md")
             |> String.split("<!-- @MODULEDOC -->")
             |> Enum.fetch!(1)
  alias Spf
  alias Spf.Context
  alias IO.ANSI

  @options [
    # <ip>, defaults to 127.0.0.1
    ip: :string,
    # <sender>, defaults to me@host.local
    sender: :string,
    # 0 error, 1 warn, 2 note, 3 info, 4 debug, default 2
    verbosity: :integer,
    # local dns RRs -> <name> SP <type> SP <value>
    rrs: :string,
    # display help and quit
    help: :boolean,
    # use color, default true
    color: :boolean
  ]

  @aliases [
    i: :ip,
    s: :sender,
    v: :verbosity,
    h: :help,
    r: :rrs,
    c: :color
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
    :cnt,
    :num_dnsm,
    :num_dnsq,
    :num_dnsv,
    :num_checks,
    :num_warn,
    :num_error,
    :duration,
    :explanation,
    :match
  ]

  # Helpers

  defp color(type, width) do
    padded = String.pad_leading("#{type}", width)

    iodata =
      case type do
        :error -> ANSI.format([:red_background, :white, padded])
        :warn -> ANSI.format([:yellow, padded])
        :note -> ANSI.format([:green, padded])
        :debug -> ANSI.format([:red, padded])
        _ -> padded
      end

    IO.iodata_to_binary(iodata)
  end

  # defp loglead(nth, facility, severity, depth) do
  #   nth = String.pad_leading("#{nth}", 2)
  #   facility = String.pad_trailing("#{facility}", 5)
  #   severity = color(severity, 5)
  #   depth = String.duplicate("| ", depth)
  #   "[spf #{nth}][#{facility}][#{severity}] #{depth}"
  # end

  # Log callback

  def log(ctx, facility, severity, msg) do
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
    {parsed, domains, _invalid} = OptionParser.parse(argv, aliases: @aliases, strict: @options)

    if Keyword.get(parsed, :help, false), do: usage()

    if Keyword.get(parsed, :color, true),
      do: Application.put_env(:elixir, :ansi_enabled, true),
      else: Application.put_env(:elixir, :ansi_enabled, false)

    parsed = Keyword.put(parsed, :log, &log/4)

    if [] == domains,
      do: do_stdin(parsed)

    for domain <- domains do
      Spf.check(domain, parsed)
      |> report(0)
      |> report(1)
      |> report(2)
      |> report(3)
      |> report(4)
      |> report(5)
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

  # Report result
  defp report(ctx, 0) do
    IO.puts("\n\n# Spfcheck #{ctx.domain}\n")

    IO.puts("```")

    Enum.map(@csv_fields, fn field -> {"#{field}", "#{ctx[field]}"} end)
    |> Enum.map(fn {k, v} -> {String.pad_trailing(k, 11, " "), v} end)
    |> Enum.map(fn {k, v} -> IO.puts("#{k}: #{v}") end)

    IO.puts("```")
    ctx
  end

  # Report Spf's
  defp report(ctx, 1) do
    IO.puts("\n## SPF records seen\n")
    nths = Map.keys(ctx.map) |> Enum.filter(fn x -> is_integer(x) end) |> Enum.sort()

    IO.puts("```")

    for nth <- nths do
      domain = ctx.map[nth]

      spf = Context.get_spf(ctx, domain)
      IO.puts("[#{nth}] #{domain}")
      IO.puts("    #{spf}")
    end

    IO.puts("```")

    ctx
  end

  # Report Prefixes
  defp report(ctx, 2) do
    IO.puts("\n## Prefixes\n")
    wseen = 5
    wpfx = 35
    indent = "    "

    spfs =
      for n <- 0..ctx.cnt do
        {n, Context.get_spf(ctx, n)}
      end
      |> Enum.into(%{})

    IO.puts("#{indent} #Seen #{String.pad_trailing("Prefixes", wpfx)} Term(s)")

    for {ip, v} <- Iptrie.to_list(ctx.ipt) do
      seen = String.pad_trailing("#{length(v)}", wseen)
      pfx = "#{ip}" |> String.pad_trailing(wpfx)

      terms =
        for {_q, nth, {_, _, slice}} <- v do
          "[#{nth}] " <> String.slice(Map.get(spfs, nth, ""), slice)
        end
        |> Enum.sort()
        |> Enum.join(", ")

      IO.puts("#{indent} #{seen} #{pfx} #{terms}")
    end

    ctx
  end

  # Report warnings
  defp report(ctx, 3) do
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

    ctx
  end

  # Report errors
  defp report(ctx, 4) do
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

    ctx
  end

  # Report DNS
  defp report(ctx, 5) do
    # return list of RRs (one for each of the rdata values)
    # so: name :a ["ip1", "ip2"] --> [{name, :a, "ip1"}, {name, :a, "ip2"}]
    rrs = fn domain, type, data ->
      domain = String.pad_trailing("#{domain}", 25)
      typestr = String.upcase("#{type}") |> String.pad_trailing(7)

      for elm <- data do
        rdata = Spf.DNS.rrdata_tostr(type, elm)
        "#{domain} #{typestr} #{inspect(rdata)}\n"
      end
    end

    IO.puts("\n## DNS\n")

    IO.puts("```")

    ctx.dns
    |> Enum.map(fn {{domain, type}, data} -> rrs.(domain, type, data) end)
    |> IO.puts()

    IO.puts("```")
  end

  def usage() do
    """

    Usage: spfcheck [options] domain

    Options:
     -c, --color          use colored output (--no-color to set this to false)
     -h, --help           prints this message and exits
     -i, --ip=string      specify sender's <ip> to check (default 127.0.0.1)
     -r, --rrs=filepath   file with DNS RR records to override live DNS
     -s, --sender=string  specify sender from address (default me@host.local)
     -v, --verbosity      set logging noise level (0..5)

    Examples:

      spfcheck example.com
      spfcheck  -i 1.1.1.1   -s someone@example.com example.com
      spfcheck --ip=1.1.1.1 --sender=someone@example.com example.com -r ./dns.txt

    DNS RR override

      DNS queries are cached and the cache can be preloaded to override the
      live DNS with specific records.  Useful to try out SPF records before
      publishing them in DNS.  The `-r` option should point to a text file
      that contains 1 RR record per line specifying the name type and rdata
      all on 1 line.  Note that the file is not in BIND format and all RR's
      must be written in full and keys are taken relative to root (.)

      Example dns.txt
        example.com  TXT  v=spf1 a mx exists:%{i}.example.net ~all
        example.com  TXT  verification=asdfi234098sf
        127.0.0.1.example.net A  127.0.0.1

      Note that each line contains a single `name type rdata` combination, so
      for multiple TXT records (e.g.) specify each on its own line, like in
      the example above.  Lines that begin with '#' or *SP'#' are ignored


    Batch mode reads from stdin

      If no domains were listen on the commandline, the domains to check are
      read from stdin, including possible flags that will override the ones
      given on the cli itself.  Note that in this case, csv output is produced
      on stdout (other logging still goes to stderr, use -v 0 to silence that)

      Examples

       % cat domains.txt | spfcheck -v 0 -i 1.1.1.1
       % cat domains.tst
         example.com -s postmaster@example.com -i 127.0.0.1
         example.net -v 5

    """
    |> IO.puts()

    exit({:shutdown, 1})
  end
end
