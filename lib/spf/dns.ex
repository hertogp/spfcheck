defmodule Spf.DNS do
  @moduledoc """
  DNS helper functions
  """

  import Spf.Context

  # https://www.rfc-editor.org/rfc/rfc6895.html
  # https://erlang.org/doc/man/inet_res.html

  @doc """
  Resolves a query and returns an `ok/error` tuple with the results.

  Returns `{:ok, [rrs]}` in case of success, `{:error, :code}` otherwise.

  """
  @spec resolve(map, binary, atom) :: {map, any}
  def resolve(ctx, name, type \\ :a) when is_map(ctx) and is_binary(name),
    do: cached(ctx, name, type) || resolved(ctx, name, type)

  defp cname(ctx, name, seen \\ %{}) do
    # return canonical name if present, name otherwise, must follow CNAME's
    name = String.trim(name) |> String.trim(".")

    if seen[name] do
      ctx =
        log(ctx, :dns, :error, "circular CNAMEs: #{inspect(seen)}")
        |> log(:dns, :info, "DNS CNAME: using #{name} to break circular reference")

      {ctx, name}
    else
      case ctx.dns[{name, :cname}] do
        nil -> {ctx, name}
        [realname] -> cname(ctx, realname, Map.put(seen, name, realname))
      end
    end
  end

  defp cached(ctx, name, type) do
    # either return nil or {ctx, res}, where res = [rrs] or {:error, reason}
    case from_cache(ctx, name, type) do
      {:ok, []} ->
        nil

      res ->
        {tick(ctx, :num_dnsq)
         |> log(
           :dns,
           :info,
           "DNS QUERY (#{ctx.num_dnsq}) - CACHE yields #{name} #{type} -> #{inspect(res)}"
         ), res}
    end
  end

  defp resolved(ctx, name, type) do
    # returns either {ctx, {:error, reason}} or {ctx, {:ok, []}} or {ctx, {:ok, [rrs]}}
    ctx =
      name
      |> String.to_charlist()
      |> :inet_res.resolve(:in, type, [{:timeout, ctx.dns_timeout}])
      |> entries()
      |> cache(ctx, name, type)

    {ctx, from_cache(ctx, name, type)}
  rescue
    x in CaseClauseError ->
      error = {:error, Exception.message(x)}

      ctx =
        Map.put(ctx, :dns, Map.put(ctx.dns, {name, type}, error))
        |> log(:dns, :error, "DNS error: #{name} #{type}: #{inspect(error)}")

      {ctx, error}

    _x in FunctionClauseError ->
      error = {:error, :illegal_name}

      ctx =
        Map.put(ctx, :dns, Map.put(ctx.dns, {name, type}, error))
        |> log(:dns, :error, "DNS ILLEGAL name: #{name}")

      {ctx, error}
  end

  @doc """
  Retrieve a record from the DNS cache `ctx.dns`.
  """
  @spec from_cache(map, binary, atom) :: {:error, any} | {:ok, list}
  def from_cache(ctx, name, type) do
    # returns either {:error, reason}, {:ok, []} or {:ok, [rrs]}
    {ctx, name} = cname(ctx, name)

    case ctx.dns[{name, type}] do
      {:error, reason} -> {:error, reason}
      nil -> {:ok, []}
      res -> {:ok, res}
    end
  end

  # cache an entry, updating various housekeeping stats
  defp cache({:error, :nxdomain} = result, ctx, name, type) do
    tick(ctx, :num_dnsq)
    |> tick(:num_dnsv)
    |> log(:dns, :error, "DNS QUERY (#{ctx.num_dnsq}) - NXDOMAIN for #{name} #{type}")
    |> Map.put(:dns, Map.put(ctx.dns, {name, type}, result))
  end

  defp cache({:error, :timeout} = result, ctx, name, type) do
    tick(ctx, :num_dnsq)
    |> log(:dns, :error, "DNS QUERY (#{ctx.num_dnsq}) - TIMEOUT for #{name} #{type}")
    |> Map.put(:dns, Map.put(ctx.dns, {name, type}, result))
  end

  defp cache({:error, {:servfail, _}} = result, ctx, name, type) do
    tick(ctx, :num_dnsq)
    |> log(:dns, :error, "DNS QUERY (#{ctx.num_dnsq}) - SERVFAIL for #{name} #{type}")
    |> Map.put(:dns, Map.put(ctx.dns, {name, type}, result))
  end

  defp cache({:error, reason}, ctx, name, type) do
    # catch all other :error reasons
    tick(ctx, :num_dnsq)
    |> log(
      :dns,
      :error,
      "DNS QUERY (#{ctx.num_dnsq}) - ERROR for #{name} #{type} - #{inspect(reason)}"
    )
    |> Map.put(:dns, Map.put(ctx.dns, {name, type}, []))
  end

  defp cache({:ok, []}, ctx, name, type) do
    tick(ctx, :num_dnsq)
    |> tick(:num_dnsv)
    |> log(:dns, :error, "DNS QUERY (#{ctx.num_dnsq}) - ZERO answers for #{name} #{type}")
    |> Map.put(:dns, Map.put(ctx.dns, {name, type}, []))
  end

  defp cache({:ok, entries}, ctx, name, type) do
    name = String.trim(name) |> String.trim(".")

    ctx =
      tick(ctx, :num_dnsq)
      |> log(:dns, :info, "DNS QUERY (#{ctx.num_dnsq}): #{name} #{type} -> #{inspect(entries)}")

    ctx = Enum.reduce(entries, ctx, fn entry, acc -> update(acc, entry) end)

    # The RR's in entries for {name, type}, might contain only CNAME's, so 
    # ensure cache has either a result or [] for {name, type}
    case from_cache(ctx, name, type) do
      {:ok, []} ->
        tick(ctx, :num_dnsv)
        |> update({name, type, []})

      _ ->
        ctx
    end
  end

  defp update(ctx, {domain, type, data}) do
    # return ctx after updating is ctx.dns if appropiate
    domain = String.trim(domain) |> String.trim(".")
    rdata = ctx.dns[{domain, type}] || []

    case data in rdata do
      true ->
        ctx

      false ->
        Map.put(ctx, :dns, Map.put(ctx.dns, {domain, type}, [data | rdata]))
        |> log(:dns, :debug, "DNS CACHED: #{domain} #{type} -> #{inspect(data)}")
    end
  end

  defp entries(msg) do
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
    {
      :inet_dns.rr(answer, :domain) |> stringify(),
      :inet_dns.rr(answer, :type),
      :inet_dns.rr(answer, :data) |> stringify()
    }
  end

  defp stringify(rrdata) when is_list(rrdata) do
    # turn a charlist or list thereof into single string
    IO.iodata_to_binary(rrdata)
  end

  defp stringify(rrdata) do
    # if not a list, keep it as it is (e.g. {a, b, c, d} for ipv4 address)
    rrdata
  end

  @doc """
  Keep only the rrdata from `rrdatas` where `fun` returns truthy.

  ## Example

      iex> DNS.resolve("www.example.com", :txt)
      ...> |> DNS.grep(fn x -> String.lower(x) |> String.contains?("v=spf1") end)
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
      |> Enum.reduce(%{}, &read_rr/2)

    ctx
    |> log(:dns, :debug, "DNS cache: #{fpath} yielded #{map_size(cache)} entries")
    |> Map.put(:dns, cache)
  rescue
    err -> log(ctx, :dns, :error, "Spf.DNS.load_file: #{Exception.message(err)}")
  end

  defp read_rr("#" <> _, ctx),
    do: ctx

  defp read_rr("", ctx),
    do: ctx

  defp read_rr(str, acc) do
    # assumes str has been trimmed already
    rr = String.split(str, ~r/ +/, parts: 3)

    case rr do
      [key, type, value] ->
        type = atomize(type)
        current = Map.get(acc, {key, type}, [])
        Map.put(acc, {key, type}, [mimic_dns(type, value) | current])

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
