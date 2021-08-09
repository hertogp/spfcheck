defmodule Spf do
  @moduledoc """
  Functions to get and debug SPF records.
  """
  alias Spfcheck.DNS
  import NimbleParsec
  import Spf.Helpers

  @doc """
  Grep for all spf-like strings found in `domain`'s `:txt` records.

  Returns an `{:ok, [binary]}` if it succeeds. Note that the list may be
  empty or may contain multiple strings, which is usually considered an
  error.  Returns `{:error, reason}` when resolving failed.

  ## Example

      iex> Spf.grep("example.com")
      {:ok, ["v=spf1 -all"]}

  """
  def grep(domain) do
    case DNS.resolve(domain, :txt) do
      {:error, reason} -> {:error, reason}
      {:ok, rdata} -> {:ok, grepp(rdata)}
    end
  end

  defp grepp(rdata) do
    rdata
    |> Enum.map(&as_string/1)
    |> Enum.filter(&spf?/1)
  end

  # check if string contains v=spf, even if malformed
  defp spf?(str) do
    str
    |> String.downcase()
    |> String.replace([" ", "\t", "\n", "\r"], "")
    |> String.contains?("v=spf")
  end

  # See https://erlang.org/doc/man/inet_res.html#type-dns_data
  # dns_data() = .. | [string()] | ..
  defp as_string(rrelement) do
    rrelement
    |> Enum.map(fn x -> List.to_string(x) end)
    |> Enum.join("")
  end

  defparsec(:parse, terms())
  defparsec(:macro, macro() |> repeat())
end
