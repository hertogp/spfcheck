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

  @doc """
  Check spf for given ip, sender and domain.
  """
  def main(argv) do
    {parsed, [domain], invalid} = OptionParser.parse(argv, aliases: @aliases, strict: @options)
    IO.inspect(parsed, label: :parsed)
    IO.inspect(domain, label: :domain)
    IO.inspect(invalid, label: :invalid)

    {verdict, explain, term} = Spf.check(domain, parsed)

    exp = if explain != "", do: " (#{explain})", else: ""
    term = if term, do: ", match by #{inspect(term)}", else: ", nothing matched"
    IO.puts("#{verdict}#{exp}#{term}")
  end
end
