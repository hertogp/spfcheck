defmodule Spf.DNS do
  @moduledoc """
  DNS helper functions
  """

  import Spf.Utils

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
    do: cached(ctx, name, type) || resolved(ctx, name, type)

  defp cached(ctx, name, type) do
    result = ctx[:dns][{name, type}]

    if result,
      do: {tick(ctx, :num_dnsq), {:ok, result}},
      else: result
  end

  defp resolved(ctx, name, type) do
    result =
      name
      |> String.to_charlist()
      |> :inet_res.resolve(:in, type)
      |> resultp()

    keys = [:dns, {name, type}]

    ctx =
      case result do
        {:error, :nxdomain} ->
          tick(ctx, :num_dnsq)
          |> tick(:num_dnsv)
          |> log(:error, "DNS #{name} #{type}: void (nxdomain)")

        {:ok, []} ->
          tick(ctx, :num_dnsq)
          |> tick(:num_dnsv)
          |> log(:error, "DNS #{name} #{type}: void (zero answers)")

        {:ok, rrs} ->
          tick(ctx, :num_dnsq) |> put_in(keys, rrs)
      end

    {ctx, result}
  rescue
    CaseClauseError ->
      keys = [Access.key(:dns), Access.key({name, type})]
      err = {:error, :qtype}
      {put_in(ctx, keys, err), err}
  end

  defp resultp(msg) do
    case msg do
      {:error, reason} -> {:error, reason}
      {:ok, record} -> {:ok, rrdata(record)}
    end
  end

  # returns the RDATA of the RR's in `record` as a list
  # See https://erlang.org/doc/man/inet_res.html#type-dns_data
  defp rrdata(record) do
    record
    |> :inet_dns.msg(:anlist)
    |> Enum.map(fn answer -> :inet_dns.rr(answer, :data) end)
    |> Enum.map(fn rrdata -> stringify(rrdata) end)
  end

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
