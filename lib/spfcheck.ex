defmodule Spfcheck do
  @external_resource "README.md"
  @moduledoc File.read!("README.md")
             |> String.split("<!-- @MODULEDOC -->")
             |> Enum.fetch!(1)
  alias Spf

  @doc """
  Check spf for given ip, sender and domain.
  """
  def main(args) do
    IO.inspect(args)
    # Spf.check(args)
  end
end
