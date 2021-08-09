defmodule Spfcheck.DNS do
  @moduledoc """
  DNS helper functions for Spfcheck.
  """

  # https://www.rfc-editor.org/rfc/rfc6895.html
  # Decimal RCODE-name Description                     Reference
  #  0      NoError    No Error                        [RFC1035]
  #  1      FormErr    Format Error                    [RFC1035]
  #  2      ServFail   Server Failure                  [RFC1035]
  #  3      NXDomain   Non-Existent Domain             [RFC1035]
  #  4      NotImp     Not Implemented                 [RFC1035]
  #  5      Refused    Query Refused                   [RFC1035]
  #  6      YXDomain   Name Exists when it should not  [RFC2136]
  #  etc..

  @doc """
  Resolves a query and returns an `ok/error` tuple with the results.

  Returns `{:ok, name, type, [rr's]}` in case of success, `{:error, :code}` otherwise.

  """
  @spec resolve(binary, atom) :: {:ok, list} | {:error, atom}
  def resolve(name, type \\ :a) do
    name
    |> String.to_charlist()
    |> :inet_res.resolve(:in, type)
    |> resultp()
  rescue
    CaseClauseError -> {:error, :qtype}
  end

  # returns {:error, reason} or {:ok, rdata}-tuple
  defp resultp(msg) do
    case msg do
      {:error, reason} -> {:error, reason}
      {:ok, record} -> {:ok, rrdata(record)}
    end
  end

  # returns the RDATA of the RR's in `record` as a list
  defp rrdata(record) do
    record
    |> :inet_dns.msg(:anlist)
    |> Enum.map(fn rr -> :inet_dns.rr(rr, :data) end)
  end
end
