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
    help: :boolean
  ]

  @doc """
  Check spf for given ip, sender and domain.
  """
  def main(argv) do
    {parsed, args, invalid} = OptionParser.parse(argv, strict: @options)
    IO.inspect(parsed, label: :parsed)
    IO.inspect(args, label: :args)
    IO.inspect(invalid, label: :invalid)
  end
end
