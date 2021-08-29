defmodule Spfcheck do
  @external_resource "README.md"
  @moduledoc File.read!("README.md")
             |> String.split("<!-- @MODULEDOC -->")
             |> Enum.fetch!(1)
  alias Spf

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

  defp loglead(nth, type, depth) do
    nth = String.pad_leading("#{nth}", 2)
    type = String.pad_leading("#{type}", 5)
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
    {parsed, [domain], invalid} = OptionParser.parse(argv, aliases: @aliases, strict: @options)
    IO.inspect(parsed, label: :parsed)
    IO.inspect(domain, label: :domain)
    IO.inspect(invalid, label: :invalid)

    parsed = [log: &log/2] ++ parsed
    {verdict, explain, term} = Spf.check(domain, parsed)

    exp = if explain != "", do: " (#{explain})", else: ""
    term = if term, do: ", match by #{inspect(term)}", else: ", nothing matched"
    IO.puts("#{verdict}#{exp}#{term}")
  end
end
