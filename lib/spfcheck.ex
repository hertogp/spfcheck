defmodule Spfcheck do
  @external_resource "README.md"
  @moduledoc File.read!("README.md")
             |> String.split("<!-- @MODULEDOC -->")
             |> Enum.fetch!(1)
  alias Spf

  @doc """
  Check spf for given ip, sender and domain.

  """
  def host(domain) do
    with {:ok, list} <- Spf.grep(domain),
         record <- List.first(list) do
      if IO.inspect(record, label: :record), do: Spf.parse(record), else: {:error, :nospf}
    else
      err -> {:error, err}
    end
  end
end
