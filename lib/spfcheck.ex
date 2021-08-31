defmodule Spfcheck do
  @external_resource "README.md"
  @moduledoc File.read!("README.md")
             |> String.split("<!-- @MODULEDOC -->")
             |> Enum.fetch!(1)
  alias Spf
  alias IO.ANSI

  @options [
    # <ip> which defaults to 127.0.0.1
    ip: :string,
    # <sender> which defaults to me@host.local
    sender: :string,
    # 0 error, 1 warn, 2 note, 3 info, 4 debug
    verbosity: :integer,
    # local dns RRs -> <name> SP <type> SP <value>
    dns: :string,
    # read args from input file, 1 invocation per line
    input: :string,
    # use csv output -> uses predefined columns:
    # domain, ip, sender, verdict, reason, explanantion, term, spf
    # csv: :boolean,
    help: :boolean,
    # use color, defaults to true
    nocolor: :boolean,
    # 0 short, 1 medium or 2 long
    report: :integer
  ]

  @aliases [
    i: :ip,
    s: :sender,
    v: :verbosity,
    h: :help,
    d: :dns,
    n: :nocolor,
    r: :report
  ]

  @verbosity %{
    :error => 0,
    :warn => 1,
    :note => 2,
    :info => 3,
    :debug => 4
  }

  @report %{
    0 => :short,
    1 => :medium,
    2 => :long
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

  def log(ctx, {type, msg}) do
    if @verbosity[type] <= ctx.verbosity do
      lead = loglead(ctx.nth, type, ctx.depth)
      IO.puts(:stderr, "#{lead} #{msg}")
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
