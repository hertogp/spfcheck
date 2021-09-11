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
           "DNS QUERY (#{ctx.num_dnsq}) - CACHE yields #{type} #{name} -> #{inspect(res)}"
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
        update(ctx, {name, type, error})
        # Map.put(ctx, :dns, Map.put(ctx.dns, {name, type}, error))
        |> log(:dns, :error, "DNS error: #{name} #{type}: #{inspect(error)}")

      {ctx, error}

    x in FunctionClauseError ->
      error = {:error, :illegal_name}

      ctx =
        update(ctx, {name, type, error})
        # Map.put(ctx, :dns, Map.put(ctx.dns, {name, type}, error))
        |> log(:dns, :error, "DNS ILLEGAL name: #{name} #{Exception.message(x)}")

      {ctx, error}
  end

  @doc """
  Retrieve RR's for given `name` from `ctx.dns`.

  """
  @spec from_cache(map, binary, atom) :: {:error, any} | {:ok, list}
  def from_cache(ctx, name, type) do
    # returns either {:error, reason}, {:ok, []} or {:ok, [rrs]}
    {ctx, name} = cname(ctx, name)

    case ctx.dns[{name, type}] do
      [{:error, reason}] -> {:error, reason}
      nil -> {:ok, []}
      res -> {:ok, res}
    end
  end

  # cache an entry, updating various housekeeping stats
  defp cache({:error, :nxdomain} = result, ctx, name, type) do
    tick(ctx, :num_dnsq)
    |> tick(:num_dnsv)
    |> log(:dns, :error, "DNS QUERY (#{ctx.num_dnsq}) - NXDOMAIN for #{type} #{name}")
    |> update({name, type, result})

    # |> Map.put(:dns, Map.put(ctx.dns, {name, type}, [result]))
  end

  defp cache({:error, :timeout} = result, ctx, name, type) do
    tick(ctx, :num_dnsq)
    |> log(:dns, :error, "DNS QUERY (#{ctx.num_dnsq}) - TIMEOUT for #{type} #{name}")
    |> update({name, type, result})

    # |> Map.put(:dns, Map.put(ctx.dns, {name, type}, result))
  end

  defp cache({:error, {:servfail, _}} = result, ctx, name, type) do
    tick(ctx, :num_dnsq)
    |> log(:dns, :error, "DNS QUERY (#{ctx.num_dnsq}) - SERVFAIL for #{type} #{name}")
    |> update({name, type, result})

    # |> Map.put(:dns, Map.put(ctx.dns, {name, type}, result))
  end

  defp cache({:error, reason} = result, ctx, name, type) do
    # catch all other :error reasons
    tick(ctx, :num_dnsq)
    |> log(
      :dns,
      :error,
      "DNS QUERY (#{ctx.num_dnsq}) - ERROR for #{type} #{name} - #{inspect(reason)}"
    )
    |> update({name, type, result})

    # |> Map.put(:dns, Map.put(ctx.dns, {name, type}, []))
  end

  defp cache({:ok, []}, ctx, name, type) do
    tick(ctx, :num_dnsq)
    |> tick(:num_dnsv)
    |> log(:dns, :warn, "DNS QUERY (#{ctx.num_dnsq}) - ZERO answers for #{type} #{name}")
    |> update({name, type, []})

    # |> Map.put(:dns, Map.put(ctx.dns, {name, type}, []))
  end

  defp cache({:ok, entries}, ctx, name, type) do
    name = String.trim(name) |> String.trim(".")

    ctx =
      tick(ctx, :num_dnsq)
      |> log(:dns, :info, "DNS QUERY (#{ctx.num_dnsq}): #{type} #{name} -> #{inspect(entries)}")

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
    # return ctx after updating ctx.dns if appropiate
    domain = stringify(domain) |> String.trim() |> String.trim(".")
    # TODO: all cache access should be via from_cache
    rdata = ctx.dns[{domain, type}] || []
    data = rr_str_data(type, data)

    case data in rdata do
      true ->
        ctx
        |> log(
          :dns,
          :debug,
          "#{type} #{domain} -> #{inspect(data)} already present in #{inspect(rdata)}"
        )

      false ->
        Map.put(ctx, :dns, Map.put(ctx.dns, {domain, type}, [data | rdata]))
        |> log(:dns, :debug, "CACHED: #{type} #{domain} -> #{inspect(data)}")
    end
  end

  # rrdata with charlists replaces by regular string (for the cache)
  defp rr_str_data(:mx, {pref, domain}),
    do: {pref, stringify(domain)}

  defp rr_str_data(type, ip) when type in [:a, :aaaa] do
    "#{Pfx.new(ip)}"
  rescue
    # in case ip is an {:error, reason}-tuple
    _ ->
      ip
  end

  defp rr_str_data(_, data),
    do: data

  def rrdata_tostr(:mx, {pref, domain}) do
    "#{pref} #{domain}"
  end

  @doc """
  Return a RR's data as a string

  """
  @spec rrdata_tostr(atom, any) :: String.t()
  def rrdata_tostr(type, ip) when type in [:a, :aaaa] and is_tuple(ip) do
    "#{Pfx.new(ip)}"
  rescue
    # since dns errors are cached as well:
    _ -> ip
  end

  def rrdata_tostr(_type, data) do
    "#{inspect(data)}"
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
    ctx =
      File.stream!(fpath)
      |> Enum.map(fn x -> String.trim(x) end)
      |> Enum.reduce(ctx, &read_rr/2)

    ctx
    |> log(:dns, :debug, "cached #{map_size(ctx.dns)} entries from #{fpath}")
  rescue
    err -> log(ctx, :dns, :error, "failed to read #{fpath}: #{Exception.message(err)}")
  end

  defp read_rr("#" <> _, ctx),
    do: ctx

  defp read_rr("", ctx),
    do: ctx

  defp read_rr(str, ctx) do
    # assumes str has been trimmed already
    case String.split(str, ~r/ +/, parts: 3) do
      [domain, type, data] ->
        type = atomize(type)
        update(ctx, {domain, type, mimic_dns(type, data)})

      _ ->
        # ignore malformed, TODO: log this as error/warning
        ctx
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

    pref =
      case Integer.parse(pref) do
        {n, ""} -> n
        _ -> pref
      end

    {pref, stringify(name)}
  end

  defp mimic_dns(_, value) do
    no_quotes(value)
  end
end
