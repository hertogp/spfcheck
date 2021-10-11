defmodule Spf.DNS do
  @moduledoc """
  DNS helper functions
  """

  import Spf.Context

  @rrtypes %{
    "a" => :a,
    "aaaa" => :aaaa,
    "cname" => :cname,
    "mx" => :mx,
    "ptr" => :ptr,
    "soa" => :soa,
    "spf" => :spf,
    "txt" => :txt
  }

  @rrerrors %{
    "timeout" => :timeout,
    "nxdomain" => :nxdomain,
    "formerr" => :formerr,
    "servfail" => :servfail,
    "zero_answers" => :zero_answers
  }

  # https://www.rfc-editor.org/rfc/rfc6895.html
  # https://erlang.org/doc/man/inet_res.html

  ## DNS cache
  # {domain, type} -> [{:error, reason}] | [{:ok, :nodata}] | [rrdata, rrdata, ..]
  # - Cache & Timeout
  #   if http://www.open-spf.org/svn/project/test-suite/ (the rfc7208 suite) is
  #   to be used to its fullest extend, the cache needs to be able to handle 
  ##  timeout's of a DNS server or the records sought after

  # Helpers

  @doc """
  Normalize a domain name: lowercase and no trailing dot.

  The DNS cache should only see lowercase names. Domain spec's should be
  normalized after expansion.

  """
  @spec normalize(String.t() | list) :: String.t()
  def normalize(domain) when is_binary(domain) do
    domain
    |> String.trim()
    |> String.replace(~r/\.$/, "")
    |> String.downcase()
  end

  def normalize(domain) when is_list(domain),
    do: List.to_string(domain) |> normalize()

  @doc """
  Checks validity of a domain name, Returns {:ok, name} or {:error, reason}

  Checks the domain name:
  - is an ascii string
  - is less than 254 chars long
  - has labels less than 64 chars long, and
  - has at least 2 labels
  """
  @spec valid?(String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def valid?(domain)

  def valid?(nil),
    do: {:error, :invalid_fqdn}

  def valid?(domain) do
    domain = normalize(domain)

    with {:ascii, true} <- {:ascii, validp?(domain, :ascii)},
         {:length, true} <- {:length, validp?(domain, :length)},
         {:labels, true} <- {:labels, validp?(domain, :labels)},
         {:multi, true} <- {:multi, validp?(domain, :multi)} do
      {:ok, domain}
    else
      {:ascii, false} -> {:error, "name contains non-ascii characters"}
      {:length, false} -> {:error, "name too long (> 254 chars long)"}
      {:labels, false} -> {:error, "name has illegal label (empty or > 63 chars)"}
      {:multi, false} -> {:error, "name not multi-label"}
      {reason, _} -> {:error, "name error: #{inspect(reason)}"}
    end
  end

  defp validp?(domain, :length),
    do: String.length(domain) < 254

  defp validp?(domain, :labels),
    do: String.split(domain, ".") |> Enum.all?(fn label -> String.length(label) in 1..63 end)

  defp validp?(domain, :multi),
    do: length(String.split(domain, ".")) > 1

  defp validp?(domain, :ascii),
    do: domain == for(<<c <- domain>>, c in 0..127, into: "", do: <<c>>)

  # Resolve

  @doc """
  Resolves a query and returns a {`ctx`, results}-tuple.

  Returns:
  - `{ctx, {:error, reason}}` if a DNS error occurred, or
  - `{ctx, {:ok, [rrs]}}` where rrs is a list of rrdata's

  Although, technically a result with ZERO answers is not a DNS error, it
  will be reported as `{:error, :zero_answers}`.

  """
  @spec resolve(map, binary, atom) :: {map, any}
  def resolve(ctx, name, type \\ :a) when is_map(ctx) do
    name = normalize(name)

    case valid?(name) do
      {:ok, name} -> resolvep(ctx, name, type)
      {:error, reason} -> {log(ctx, :dns, :error, "#{reason}"), {:error, :illegal_name}}
    end
  end

  defp resolvep(ctx, name, type) do
    case from_cache(ctx, name, type) do
      {:error, :cache_miss} ->
        query(ctx, name, type)

      result ->
        do_stats(ctx, name, type, result, cached: true)
    end
  end

  defp query(ctx, name, type) do
    # returns either {ctx, {:error, reason}} or {ctx, {:ok, [rrs]}}
    timeout = Map.get(ctx, :dns_timeout, 2000)

    ctx =
      name
      |> String.to_charlist()
      |> :inet_res.resolve(:in, type, [{:timeout, timeout}])
      |> rrentries()
      |> cache(ctx, name, type)

    result = from_cache(ctx, name, type)
    do_stats(ctx, name, type, result)
  rescue
    x in CaseClauseError ->
      error = {:error, Exception.message(x)}

      ctx =
        update(ctx, {name, type, error})
        |> log(:dns, :error, "DNS error!: #{name} #{type}: #{inspect(error)}")

      {ctx, error}

    x in FunctionClauseError ->
      error = {:error, :illegal_name}

      ctx =
        update(ctx, {name, type, error})
        |> log(:dns, :error, "DNS ILLEGAL name: #{name} #{Exception.message(x)}")

      {ctx, error}
  end

  defp do_stats(ctx, name, type, result, opts \\ []) do
    # return ctx with updated stats and possibly updated result
    qry =
      case Keyword.get(opts, :cached, false) do
        true -> "DNS QUERY (#{ctx.num_dnsq}) [cache] #{type} #{name}"
        false -> "DNS QUERY (#{ctx.num_dnsq}) #{type} #{name}"
      end

    case result do
      {:error, :cache_miss} ->
        # result didn't include an answer for given `type`
        result = {:error, :zero_answers}

        {update(ctx, {name, type, result})
         |> tick(:num_dnsv)
         |> tick(:num_dnsq)
         |> log(:dns, :warn, "#{qry} - ZERO answers"), result}

      {:error, :zero_answers} ->
        # result didn't include any answers
        {tick(ctx, :num_dnsv)
         |> tick(:num_dnsq)
         |> log(:dns, :warn, "#{qry} - ZERO answers"), result}

      {:error, :nxdomain} ->
        {tick(ctx, :num_dnsv)
         |> tick(:num_dnsq)
         |> log(:dns, :warn, "#{qry} - NXDOMAIN"), result}

      {:error, reason} ->
        # any other error, like :servfail
        err = String.upcase("#{inspect(reason)}")

        {log(ctx, :dns, :warn, "#{qry} - #{err}")
         |> tick(:num_dnsq), result}

      {:ok, res} ->
        {log(ctx, :dns, :info, "#{qry} - #{inspect(res)}")
         |> tick(:num_dnsq), result}
    end
  end

  defp rrentries(msg) do
    # given a dns_msg {:dns_rec, ...} or error-tuple
    # -> return either: {:ok, [{domain, type, value}, ...]} | {:error, reason}
    case msg do
      {:error, reason} -> {:error, reason}
      {:ok, record} -> {:ok, rrdata(record)}
    end
  end

  defp rrdata(record) do
    # turn dns record into list of simple rrdata entries: [{domain, type, data}]
    # see https://erlang.org/doc/man/inet_res.html#type-dns_data
    record
    |> :inet_dns.msg(:anlist)
    |> Enum.map(fn x -> rrentry(x) end)
  end

  defp rrentry(answer) do
    # {:dns_rr, :domain, :type, :in, _, _, :data, :undefined, [], false}
    # -> {domain, type, data}, where shape of data depends on type
    # .e.g :mx -> {10, name}, :a -> {1, 1, 1, 1}, etc ..
    domain = :inet_dns.rr(answer, :domain) |> charlists_tostr()
    type = :inet_dns.rr(answer, :type)
    data = :inet_dns.rr(answer, :data) |> charlists_tostr(type)
    {domain, type, data}
  end

  # Cache

  @doc """
  Returns a cache hit or miss for given `name` and `type` from cache `ctx.dns`.

  - `{:ok, []}` is a cache miss.
  - `{:error, reason}` is a cache hit for a previous negative result
  - `{:ok, rrs}` is a cache hit where `rrs` is a list of rrdata's.

  """
  @spec from_cache(map, binary, atom) :: {:error, atom} | {:ok, list}
  def from_cache(ctx, name, type) do
    # returns either {:error, reason} or {:ok, [rrs]}
    {ctx, name} = cname(ctx, name)
    cache = Map.get(ctx, :dns, %{})

    case cache[{name, type}] do
      nil -> {:error, :cache_miss}
      [{:error, reason}] -> {:error, reason}
      res -> {:ok, res}
    end
  end

  defp cname(ctx, name, seen \\ %{}) do
    # return canonical name if present, name otherwise, must follow CNAME's
    # name = charlists_tostr(name) |> String.trim() |> String.trim(".")
    name = charlists_tostr(name) |> normalize()
    cache = Map.get(ctx, :dns, %{})

    if seen[name] do
      ctx =
        log(ctx, :dns, :error, "circular CNAMEs: #{inspect(seen)}")
        |> log(:dns, :warn, "DNS CNAME: using #{name} to break circular reference")

      {ctx, name}
    else
      case cache[{name, :cname}] do
        nil -> {ctx, name}
        [{:error, _}] -> {ctx, name}
        [realname] -> cname(ctx, realname, Map.put(seen, name, realname))
      end
    end
  end

  # cache an {:error, reason} or data entry for given `name` and `type`
  # note that `name` and `type` come from the {:dns_rr, ..}-record itself.
  defp cache({:error, {:servfail, _reason}} = _result, ctx, name, type),
    do: update(ctx, {name, type, {:error, :servfail}})

  defp cache({:error, _reason} = result, ctx, name, type),
    do: update(ctx, {name, type, result})

  defp cache({:ok, []}, ctx, name, type),
    do: update(ctx, {name, type, {:error, :zero_answers}})

  defp cache({:ok, entries}, ctx, _name, _type),
    do: Enum.reduce(entries, ctx, fn entry, acc -> update(acc, entry) end)

  defp update(ctx, {domain, type, data}) do
    # note: donot use from_cache since that unrolls cnames
    domain = normalize(domain)
    cache = Map.get(ctx, :dns, %{})
    cached = cache[{domain, type}] || []
    data = charlists_tostr(data, type)

    case data in cached do
      true -> ctx
      false -> Map.put(ctx, :dns, Map.put(cache, {domain, type}, [data | cached]))
    end
  end

  # charlists_tostr -> turn any charlists *inside* rrdata into a string.
  # note:
  # - empty list should turn into {:error, :zero_answers}, and NOT ""
  # - {:error, _} should stay an error-tuple
  defp charlists_tostr([]),
    do: {:error, :zero_answers}

  defp charlists_tostr(rrdata) when is_list(rrdata) do
    # turn a single (non-empty) charlist or list of charlists into single string
    # this glues the strings together without spaces.
    IO.iodata_to_binary(rrdata)
  end

  defp charlists_tostr(rrdata) do
    # catch all, keep it as it is
    rrdata
  end

  # no charlist in error situations
  defp charlists_tostr({:error, reason}, _),
    do: {:error, reason}

  # mta name to string
  defp charlists_tostr({pref, domain}, :mx),
    do: {pref, charlists_tostr(domain)}

  # txt value to string
  defp charlists_tostr(txt, :txt) do
    charlists_tostr(txt)
  end

  # domain name of ptr record to string
  defp charlists_tostr(domain, :ptr),
    do: charlists_tostr(domain)

  # address tuple to string (or keep {:error,_}-tuple)
  defp charlists_tostr(ip, :a) do
    "#{Pfx.new(ip)}"
  rescue
    _ -> ip
  end

  # address tuple to string (or keep {:error,_}-tuple)
  defp charlists_tostr(ip, :aaaa) do
    "#{Pfx.new(ip)}"
  rescue
    _ -> ip
  end

  # primary nameserver and admin contact to string
  defp charlists_tostr({mname, rname, serial, refresh, retry, expiry, min_ttl}, :soa),
    do: {charlists_tostr(mname), charlists_tostr(rname), serial, refresh, retry, expiry, min_ttl}

  defp charlists_tostr(data, _) when is_list(data),
    do: charlists_tostr(data)

  defp charlists_tostr(data, _),
    do: data

  @doc """
  Return all acquired DNS RR's in a flat list of printable lines.

  Note that RR's with multiple entries in their rrdata are listed individually,
  so the output can be copy/paste'd into a local dns.txt pre-cache to facilitate
  experimentation with RR records.

  """
  def to_list(ctx, opts \\ []) do
    valid = Keyword.get(opts, :valid, true)
    cache = Map.get(ctx, :dns, %{})

    cache
    |> Enum.map(fn {{domain, type}, data} -> rr_flatten(domain, type, data) end)
    |> List.flatten()
    |> rrs_sort()
    |> Enum.filter(fn {_domain, _type, data} -> valid != rr_is_error(data) end)
    |> Enum.map(fn {domain, type, data} -> rr_tostr(domain, type, data) end)
  end

  defp rr_flatten(domain, type, data) do
    for rrdata <- data do
      {domain, type, rrdata}
    end
  end

  defp rrs_sort(rrs) do
    # keeps related records close to each other in report output
    Enum.sort(rrs, fn {domain1, _type, _data}, {domain2, _type1, _data2} ->
      String.reverse(domain1) <= String.reverse(domain2)
    end)
  end

  defp rr_is_error(data) do
    case data do
      {:error, _} -> true
      _ -> false
    end
  end

  defp rr_data_maybe_error(data) do
    error = no_quotes(data) |> String.downcase()

    case @rrerrors[error] do
      nil -> data
      error -> {:error, error}
    end
  end

  def rr_fromstr(str, ctx),
    do: String.trim(str) |> rr_fromstrp(ctx)

  defp rr_fromstrp("#" <> _, ctx),
    # this is why str must be trimmed already
    do: ctx

  defp rr_fromstrp("", ctx),
    do: ctx

  defp rr_fromstrp(str, ctx) do
    case String.split(str, ~r/\s+(A|AAAA|MX|PTR|TXT|SPF|SOA|CNAME)\s+/i,
           parts: 2,
           include_captures: true
         ) do
      # Nb: included capture(s) are NOT counted agains the limit set by parts:
      [domain, type, data] ->
        type = rr_type(type)
        update(ctx, {domain, type, rr_data_fromstr(type, data)})

      [unsplit] ->
        words = String.split(unsplit, ~r/\s+/)
        data = List.last(words)
        domain = List.delete_at(words, -1) |> Enum.join("") |> normalize()

        Enum.reduce(@rrtypes, ctx, fn {_name, type}, ctx ->
          update(ctx, {domain, type, {:error, rr_error(data)}})
        end)

      _ ->
        # ignore malformed, TODO: log this as error/warning
        ctx
    end
  end

  defp rr_tostr(domain, type, data) do
    domain = String.pad_trailing(domain, 25) |> String.downcase()
    rrtype = String.upcase("#{type}") |> String.pad_trailing(7)
    data = rr_data_tostr(type, data)
    Enum.join([domain, rrtype, data], " ")
  end

  # TODO: rr_data_fromstr
  # - check validity of supplied data (e.g. IP addresses)
  # - support error entries, e.g. like <domain> <type> :nxdomain
  #   -> this would also mean <domain> <other_type> should be :error :nxdomain (!)
  #   -> same goes for :servfail and maybe others ...
  #   -> but not for e.g. :error :zero_answers or :timeout (!)
  defp rr_data_fromstr(:mx, value) do
    parts = no_quotes(value) |> String.downcase() |> String.split(~r/\s+/, parts: 2)

    case parts do
      [pref, name] ->
        pref =
          case Integer.parse(pref) do
            {n, ""} -> n
            _ -> pref
          end

        {pref, charlists_tostr(name)}

      [err] ->
        {:error, @rrerrors[err] || err}
    end
  end

  defp rr_data_fromstr(:aaaa, value) do
    String.downcase(value)
  end

  defp rr_data_fromstr(:ptr, value) do
    String.downcase(value)
  end

  defp rr_data_fromstr(_, value) do
    no_quotes(value) |> rr_data_maybe_error()
  end

  @spec rr_data_tostr(atom, any) :: String.t()
  defp rr_data_tostr(_, {:error, reason}),
    do: "#{inspect(reason)}" |> String.upcase() |> String.trim_leading(":")

  defp rr_data_tostr(type, ip) when type in [:a, :aaaa] and is_tuple(ip) do
    "#{Pfx.new(ip)}"
  rescue
    # since dns errors are cached as well:
    _ -> ip
  end

  defp rr_data_tostr(:mx, {pref, domain}) do
    "#{pref} #{domain}"
  end

  defp rr_data_tostr(:txt, txt) do
    inspect(txt)
  end

  defp rr_data_tostr(_type, data) do
    "#{inspect(data)}" |> no_quotes()
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

  # From File/Strings

  def load_file(ctx, nil), do: ctx

  def load_file(ctx, fpath) when is_binary(fpath) do
    ctx =
      case File.read(fpath) do
        {:ok, binary} ->
          load_lines(ctx, String.split(binary, "\n"))

        {:error, reason} ->
          log(ctx, :dns, :error, "failed to read #{fpath}: #{inspect(reason)}")
      end

    log(ctx, :dns, :debug, "cached #{map_size(ctx.dns)} entries from #{fpath}")
  rescue
    err -> log(ctx, :dns, :error, "failed to read #{fpath}: #{Exception.message(err)}")
  end

  def load_lines(ctx, lines) when is_list(lines) do
    lines
    |> Enum.map(&String.trim/1)
    |> Enum.reduce(ctx, &rr_fromstr/2)
  end

  defp rr_type(type) do
    type = String.trim(type) |> String.downcase()
    @rrtypes[type] || String.upcase(type)
  end

  defp rr_error(error),
    do: @rrerrors[String.downcase(error)] || String.upcase(error)

  defp no_quotes(str) do
    str
    |> String.replace(~r/^\"/, "")
    |> String.replace(~r/\"$/, "")
  end
end
