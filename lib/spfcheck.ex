defmodule Spfcheck do
  @external_resource "README.md"
  @moduledoc File.read!("README.md")
             |> String.split("<!-- @MODULEDOC -->")
             |> Enum.fetch!(1)
  alias Spf
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

  # Helpers

  defp color(type, width) do
    padded = String.pad_leading("#{type}", width)

    iodata =
      case type do
        :error -> ANSI.format([:red_background, :white, padded])
        :warn -> ANSI.format([:yellow, padded])
        :note -> ANSI.format([:green, padded])
        :debug -> ANSI.format([:white_background, :red, padded])
        _ -> padded
      end

    IO.iodata_to_binary(iodata)
  end

  defp loglead(nth, type, depth) do
    nth = String.pad_leading("#{nth}", 2)
    type = color(type, 5)
    depth = String.duplicate("| ", depth)
    "[spf #{nth}][#{type}] #{depth}"
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
      spfcheck -i 1.1.1.1 -s someone@example.com example.com
      spfcheck --ip=1.1.1.1 --sender=someone@example.com example.com -r ./dns.txt

    DNS RR override

      DNS queries are cached and the cache can be preloaded to override the
      live DNS with specific records.  Useful to try out SPF records before
      publishing them in DNS.  The `-r` option should point to a text file
      that contains 1 RR record per line specifying the key, type and value
      all on 1 line.  Note that the file is not in BIND format and all RR's
      must be written in full and keys are taken relative to root (.)

      Example dns.txt
        example.com  TXT  v=spf1 a mx exists:%{i}.example.net ~all
        127.0.0.1.example.net A  127.0.0.1


    Read from stdin

      If no domains were listen on the commandline, the domains to check are
      read from stdin, including possible flags that will override the ones
      given on the cli itself.  Note that in this case, csv output is produced
      on stdout (other logging still goes to stderr, use -v 0 to silence that)


    """
  end

  # Log callback

  def log(ctx, {type, msg}) do
    if @verbosity[type] <= ctx.verbosity do
      lead = loglead(ctx.nth, type, ctx.depth)
      IO.puts(:stderr, "#{lead}#{msg}")
    end
  end

  def log(ctx, {type, {_token, _tokval, range}, msg}) do
    if @verbosity[type] <= ctx.verbosity do
      tokstr = String.slice(ctx[:spf], range)
      lead = loglead(ctx.nth, type, ctx.depth)
      IO.puts(:stderr, "#{lead}> #{tokstr} - #{msg}")
    end
  end

  # MAIN

  @doc """
  Check spf for given ip, sender and domain.
  """
  def main(argv) do
    {parsed, domains, _invalid} = OptionParser.parse(argv, aliases: @aliases, strict: @options)

    unless Keyword.get(parsed, :nocolor, false),
      do: Application.put_env(:elixir, :ansi_enabled, true)

    IO.inspect(argv, label: :argv)
    IO.inspect({parsed, domains}, label: :cli)

    if Keyword.get(parsed, :help, false) do
      IO.puts(usage())
      exit({:shutdown, 1})
    end

    # -b -> do batch mode handling (output is csv)
    # domains = [] -> read stdin (output is csv)

    for domain <- domains do
      IO.puts("\nspfcheck on #{domain}, opts #{inspect(parsed)}")
      parsed = [log: &log/2] ++ parsed
      {verdict, explain, term} = Spf.check(domain, parsed)

      exp = if explain != "", do: " (#{explain})", else: ""
      term = if term, do: ", match by #{inspect(term)}", else: ", nothing matched"
      IO.puts("#{verdict}#{exp}#{term}")
    end
  end
end
