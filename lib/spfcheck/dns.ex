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

  # See https://erlang.org/doc/man/inet_res.html

  @doc """
  Resolves a query and returns an `ok/error` tuple with the results.

  Returns `{:ok, [rr's]}` in case of success, `{:error, :code}` otherwise.

  """
  @spec resolve(map, binary, atom) :: {map, any}
  def resolve(ctx, name, type \\ :a) when is_map(ctx) and is_binary(name),
    do: cached(ctx, name, type) || cache(ctx, name, type)

  defp cached(ctx, name, type) do
    result = ctx[:dns][{name, type}]
    IO.inspect(result, label: :dns_cached)

    if result,
      do: {ctx, result},
      else: result
  end

  defp cache(ctx, name, type) do
    result =
      name
      |> String.to_charlist()
      |> :inet_res.resolve(:in, type)
      |> resultp()

    keys = [Access.key(:dns), Access.key({name, type})]
    {put_in(ctx, keys, result), result}
  rescue
    CaseClauseError ->
      keys = [Access.key(:dns), Access.key({name, type})]
      err = {:error, :qtype}
      {put_in(ctx, keys, err), err}
  end

  # returns {:error, reason} or {:ok, rdata}-tuple
  # DNS Return Message
  # DNS Response Code     Function 
  # NOERROR      RCODE:0  DNS Query completed successfully
  # FORMERR      RCODE:1  DNS Query Format Error
  # SERVFAIL     RCODE:2  Server failed to complete the DNS request
  # NXDOMAIN     RCODE:3  Domain name does not exist.
  # NOTIMP       RCODE:4  Function not implemented
  # REFUSED      RCODE:5  The server refused to answer for the query
  # YXDOMAIN     RCODE:6  Name that should not exist, does exist
  # XRRSET       RCODE:7  RRset that should not exist, does exist
  # NOTAUTH      RCODE:8  Server not authoritative for the zone
  # NOTZONE      RCODE:9  Name not in zone

  defp resultp(msg) do
    IO.inspect(msg, label: :resolve)

    case msg do
      {:error, reason} -> {:error, reason}
      {:ok, record} -> {:ok, rrdata(record)}
    end
  end

  # returns the RDATA of the RR's in `record` as a list
  # See https://erlang.org/doc/man/inet_res.html#type-dns_data
  # - record must have answer list (i.e. resolve() was :ok)
  # - :anlist is a list of rr-tuples
  # - an rr-tuple has {:dns_rr, domain, type, class, ttl, data} (or variant with options)
  # - inet_dns.rr(rr-tuple, :atom) -> field-value, where atoms are :domain, .., :data
  # - rrdata can be: a charlist, {addr, soa, ..}--tuple, binary, list of charlists
  defp rrdata(record) do
    record
    |> :inet_dns.msg(:anlist)
    |> Enum.map(fn answer -> :inet_dns.rr(answer, :data) end)
    |> Enum.map(fn rrdata -> stringify(rrdata) end)
  end

  # turn a charlist or list of charlists into single string
  defp stringify(rrdata) when is_list(rrdata),
    do: IO.iodata_to_binary(rrdata)

  defp stringify(rrdata),
    do: rrdata

  @doc """
  Keep only the rrdata from `rrdatas` where `fun` returns truthy.

  ## Example

      iex> DNS.resolve("www.example.com", :txt)
      ...> |> DNS.grep(fn x -> String.contains?("spf") end)
      ["v=spf1 -all"]

  """
  def grep({:ok, rrdatas}, fun),
    do: grep(rrdatas, fun)

  def grep({:error, reason}, _fun),
    do: {:error, reason}

  def grep(rrdatas, fun) when is_function(fun, 1),
    do: {:ok, Enum.filter(rrdatas, fn rrdata -> fun.(rrdata) end)}
end
