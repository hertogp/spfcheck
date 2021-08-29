defmodule Spfcheck do
  @external_resource "README.md"
  @moduledoc File.read!("README.md")
             |> String.split("<!-- @MODULEDOC -->")
             |> Enum.fetch!(1)
  alias Spf
  alias IO.ANSI

  @options [
    ip: :string,
    sender: :string,
    verbosity: :integer,
    dns: :string,
    input: :string,
    csv: :boolean,
    help: :boolean,
    local: :string
  ]

  @aliases [
    i: :ip,
    s: :sender,
    v: :verbosity,
    h: :help,
    l: :local
  ]

  # Helpers

  defp color(type, width) do
    padded = String.pad_leading("#{type}", width)

    iodata =
      case type do
        :error -> ANSI.format([:red_background, :white, padded])
        :warn -> ANSI.format([:yellow_background, :black, padded])
        :note -> ANSI.format([:green, padded])
        :debug -> ANSI.format([:red, padded])
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
    lead = loglead(ctx.nth, type, ctx.depth)
    IO.puts(:stderr, "#{lead} #{msg}")
  end

  def log(ctx, {type, {_token, _tokval, range}, msg}) do
    tokstr = String.slice(ctx[:spf], range)
    lead = loglead(ctx.nth, type, ctx.depth)
    IO.puts(:stderr, "#{lead}> #{tokstr} - #{msg}")
  end

  # MAIN

  @doc """
  Check spf for given ip, sender and domain.
  """
  def main(argv) do
    Application.put_env(:elixir, :ansi_enabled, true)
    {parsed, [domain], _invalid} = OptionParser.parse(argv, aliases: @aliases, strict: @options)
    parsed = [log: &log/2] ++ parsed
    {verdict, explain, term} = Spf.check(domain, parsed)

    exp = if explain != "", do: " (#{explain})", else: ""
    term = if term, do: ", match by #{inspect(term)}", else: ", nothing matched"
    IO.puts("#{verdict}#{exp}#{term}")
  end
end
