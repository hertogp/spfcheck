defmodule Spfcheck do
  @external_resource "README.md"
  @moduledoc File.read!("README.md")
             |> String.split("<!-- @MODULEDOC -->")
             |> Enum.fetch!(1)
  alias Spf

  @doc """
  Check spf for given ip, sender and domain.

  """
  def host(domain),
    do: Spf.check(domain)
end
