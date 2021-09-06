defmodule Spf.DNS do
  @moduledoc """
  DNS helper functions
  """

  import Spf.Context

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

  defp cname(ctx, name) do
    # return canonical name if present (TODO: tick num_dnsq counter?)
    case ctx.dns[{name, :cname}] do
      nil -> {ctx, name}
      [realname] -> {log(ctx, :note, "DNS CNAME: #{name} -> #{realname}"), realname}
    end
  end

  defp cached(ctx, name, type) do
    {ctx, name} = cname(ctx, name)
    result = ctx.dns[{name, type}]

    if result do
      ctx =
        tick(ctx, :num_dnsq)
        |> log(:debug, "DNS cache: #{name} #{type} #{inspect(result)}")

      {ctx, {:ok, result}}
    else
      # return nil if not cached
      result
    end
  end

  defp resolved(ctx, name, type) do
    {ctx, name} = cname(ctx, name)

    ctx =
      name
      |> String.to_charlist()
      |> :inet_res.resolve(:in, type, [{:timeout, ctx.dns_timeout}])
      |> results()
      |> cache(ctx, name, type)

    IO.inspect(ctx.dns, label: :resolved_cached)
    {ctx, {:ok, ctx.dns[{name, type}]}}
  rescue
    x in CaseClauseError ->
      error = {:error, Exception.message(x)}

      ctx =
        Map.put(ctx, :dns, Map.put(ctx.dns, {name, type}, error))
        |> log(:error, "DNS error: #{name} #{type}: #{inspect(error)}")

      {ctx, error}

    x in FunctionClauseError ->
      IO.inspect(x, label: :illegal_name)
      error = {:error, :illegal_name}

      ctx =
        Map.put(ctx, :dns, Map.put(ctx.dns, {name, type}, error))
        |> log(:error, "DNS ILLEGAL name: #{name}")

      {ctx, error}
  end

  defp cache({:error, :nxdomain} = result, ctx, name, type) do
    tick(ctx, :num_dnsq)
    |> tick(:num_dnsv)
    |> log(:debug, "DNS NXDOMAIN: #{name} #{type}")
    |> Map.put(:dns, Map.put(ctx.dns, {name, type}, result))
  end

  defp cache({:error, :timeout} = result, ctx, name, type) do
    tick(ctx, :num_dnsq)
    |> log(:error, "DNS TIMEOUT: #{name} #{type}")
    |> Map.put(:dns, Map.put(ctx.dns, {name, type}, result))
  end

  defp cache({:error, {:servfail, _}} = result, ctx, name, type) do
    tick(ctx, :num_dnsq)
    |> log(:error, "DNS SERVFAIL: #{name} #{type}")
    |> Map.put(:dns, Map.put(ctx.dns, {name, type}, result))
  end

  defp cache({:error, reason}, ctx, name, type) do
    # catch all other :error reasons
    tick(ctx, :num_dnsq)
    |> log(:error, "DNS error: #{name} #{type} - #{inspect(reason)}")
    |> Map.put(:dns, Map.put(ctx.dns, {name, type}, []))
  end

  defp cache({:ok, []}, ctx, name, type) do
    tick(ctx, :num_dnsq)
    |> tick(:num_dnsv)
    |> log(:debug, "DNS ZERO answers: #{name} #{type}")
    |> Map.put(:dns, Map.put(ctx.dns, {name, type}, []))
  end

  defp cache({:ok, entries}, ctx, name, type) do
    ctx =
      tick(ctx, :num_dnsq)
      |> log(:debug, "DNS QUERY: #{name} #{type} #{inspect(entries)}")

    # update {name, type} -> [entries]
    Enum.reduce(entries, ctx, fn {domain, type, data}, acc ->
      Map.put(acc, :dns, Map.update(acc.dns, {domain, type}, [data], fn x -> [data | x] end))
    end)
  end

  defp results(msg) do
    case msg do
      {:error, reason} -> {:error, reason}
      {:ok, record} -> {:ok, rrdata(record)}
    end
  end

  defp rrdata(record) do
    # turn dns record into list of entries: [{domain, type, data}]
    # see https://erlang.org/doc/man/inet_res.html#type-dns_data
    record
    |> :inet_dns.msg(:anlist)
    |> Enum.map(fn x -> rrentry(x) end)
  end

  defp rrentry(answer) do
    {:inet_dns.rr(answer, :domain) |> stringify(), :inet_dns.rr(answer, :type),
     :inet_dns.rr(answer, :data) |> stringify()}
  end

  defp stringify(rrdata) when is_list(rrdata) do
    IO.iodata_to_binary(rrdata)
  end

  defp stringify(rrdata) do
    # looks like this is not needed ..
    IO.inspect(rrdata, label: :stringify2)
    List.to_string(rrdata)
  end

  @doc """
  Keep only the rrdata from `rrdatas` where `fun` returns truthy.

  ## Example

      iex> DNS.resolve("www.example.com", :txt)
      ...> |> DNS.grep(fn x -> String.contains?("v=spf1") end)
      ["v=spf1 -all"]

  """
  def grep({:ok, rrdatas}, fun),
    do: grep(rrdatas, fun)

  def grep({:error, reason}, _fun),
    do: {:error, reason}

  def grep(rrdatas, fun) when is_function(fun, 1),
    do: {:ok, Enum.filter(rrdatas, fn rrdata -> fun.(rrdata) end)}

  def load_file(ctx, nil), do: ctx

  def load_file(ctx, fpath) when is_binary(fpath) do
    cache =
      File.stream!(fpath)
      |> Enum.map(fn x -> String.trim(x) end)
      |> Enum.filter(fn x -> not String.starts_with?(x, "#") end)
      |> Enum.filter(fn x -> String.length(x) > 0 end)
      |> Enum.reduce(%{}, &read_rr/2)

    ctx
    |> log(:debug, "DNS cache: #{fpath} yielded #{map_size(cache)} entries")
    |> Map.put(:dns, cache)
  rescue
    err -> log(ctx, :error, "Spf.DNS.load_file: #{Exception.message(err)}")
  end

  defp read_rr(str, acc) do
    # assumes str has been trimmed already
    rr = String.split(str, ~r/ +/, parts: 3)

    case rr do
      [key, type, value] ->
        type = atomize(type)
        current = Map.get(acc, {key, type}, [])
        Map.put(acc, {key, type}, [{:ok, mimic_dns(type, value)} | current])

      _ ->
        # ignore malformed, TODO: log this as error/warning
        acc
    end
  end

  defp atomize(type) do
    case String.downcase(type) do
      "txt" -> :txt
      "a" -> :a
      "aaaa" -> :aaaa
      "ptr" -> :ptr
      "spf" -> :spf
      "mx" -> :mx
      "cname" -> :cname
      _ -> type
    end
  end

  defp no_quotes(str) do
    str
    |> String.replace(~r/^\"/, "")
    |> String.replace(~r/\"$/, "")
  end

  defp mimic_dns(:mx, value) do
    {pref, name} =
      value
      |> no_quotes()
      |> String.split(~r/\s+/, parts: 2)
      |> List.to_tuple()

    {pref, String.to_charlist(name)}
  end

  defp mimic_dns(_, value) do
    no_quotes(value)
  end
end
