defmodule Spf.DNS do
  @moduledoc """
  DNS helper functions
  """

  import Spf.Context

  # https://www.rfc-editor.org/rfc/rfc6895.html
  # https://erlang.org/doc/man/inet_res.html

  # TODO:
  # DNS RESOLVE -> {:error, reason} | {:ok, []}
  # - inet_res.lookup -> list of rrdatas only:
  #   :inet_res.lookup('yahoo.com', :in, :a)  
  #   [
  #     {98, 137, 11, 163},
  #     {74, 6, 143, 26},
  #     {74, 6, 231, 20},
  #     {74, 6, 143, 25},
  #     {98, 137, 11, 164},
  #     {74, 6, 231, 21}
  #   ]
  #   In case of any type of error, you get a [] which could mean
  #   nxdomain, servfail or timeout etc ...  This also hides any
  #   CNAME's that might be in play...  So we use :inet_res.resolve()
  #
  # :inet_res.resolve('mlzopendata.cbs.nl', :in, :mx) -> {:ok, :zero_answer}
  # {:ok,
  # {:dns_rec, {:dns_header, 20, true, :query, false, false, true, true, false, 0},
  #  [{:dns_query, 'mlzopendata.cbs.nl', :mx, :in}],
  #  [
  #    {:dns_rr, 'mlzopendata.cbs.nl', :cname, :in, 0, 2724, 'adc4.cbs.nl',
  #     :undefined, [], false}
  #  ], [], []}}
  #
  # :inet_res.resolve('380kv.nl', :in, :mx) -> {:error, :servfail}
  # {:error,
  # {:servfail,
  #  {:dns_rec,
  #   {:dns_header, 21, true, :query, false, false, true, true, false, 2},
  #   [{:dns_query, '380kv.nl', :mx, :in}], [], [], []}}}
  # - :inet_res.resolve('yahoo.com', :in, :a) 
  # {:ok,
  #   {:dns_rec,
  #     {:dns_header, 18, true, :query, false, false, true, true, false, 0},            # header
  #     [{:dns_query, 'yahoo.com', :a, :in}],                                           # qdlist
  #     [
  #       {:dns_rr, 'yahoo.com', :a, :in, 0, 330, {74, 6, 231, 20}, :undefined, [],
  #        false},
  #       {:dns_rr, 'yahoo.com', :a, :in, 0, 330, {98, 137, 11, 164}, :undefined, [],
  #        false},
  #       {:dns_rr, 'yahoo.com', :a, :in, 0, 330, {74, 6, 143, 25}, :undefined, [],
  #        false},
  #       {:dns_rr, 'yahoo.com', :a, :in, 0, 330, {98, 137, 11, 163}, :undefined, [],
  #        false},
  #       {:dns_rr, 'yahoo.com', :a, :in, 0, 330, {74, 6, 143, 26}, :undefined, [],
  #        false},
  #       {:dns_rr, 'yahoo.com', :a, :in, 0, 330, {74, 6, 231, 21}, :undefined, [],
  #        false}
  #     ],                                                                              # anlist
  #     [],                                                                             # nslist
  #     []                                                                              # arlist
  #    }
  #  }
  #  Now we need to:
  #  - get RCODE from dns msg's header
  #    {:ok, msg} = :inet_resolve('domain', :in, :type)
  #    hdr = :inet_dns.header(msg) -> {:dns_header, 18, true, :query, false, false, true, true, false, 0}
  #    rcode = :inet_dns.msg(msg, :header) |> :inet_dns.header(:rcode)
  #  - RR's from dns msg's answer list
  #    :inet_dns.msg(msg, :anlist)                            
  #    [
  #      {:dns_rr, 'yahoo.com', :a, :in, 0, 1664, {74, 6, 143, 26}, :undefined, [], false},
  #      {:dns_rr, 'yahoo.com', :a, :in, 0, 1664, {74, 6, 143, 25}, :undefined, [], false},
  #      {:dns_rr, 'yahoo.com', :a, :in, 0, 1664, {98, 137, 11, 164}, :undefined, [], false},
  #      {:dns_rr, 'yahoo.com', :a, :in, 0, 1664, {74, 6, 231, 21}, :undefined, [], false},
  #      {:dns_rr, 'yahoo.com', :a, :in, 0, 1664, {98, 137, 11, 163}, :undefined, [], false},
  #      {:dns_rr, 'yahoo.com', :a, :in, 0, 1664, {74, 6, 231, 20}, :undefined, [], false}
  #    ]
  #  - convert for each rr in the list of rrs, eg
  #    :inet_dns.msg(msg, :anlist) |> hd() |> :inet_dns.rr(:domain) -> 'yahoo.com'
  #    :inet_dns.msg(msg, :anlist) |> hd() |> :inet_dns.rr(:type)  -> :a
  #    :inet_dns.msg(msg, :anlist) |> hd() |> :inet_dns.rr(:class)   -> :in
  #    :inet_dns.msg(msg, :anlist) |> hd() |> :inet_dns.rr(:ttl)  -> 1664
  #    :inet_dns.msg(msg, :anlist) |> hd() |> :inet_dns.rr(:data) -> {74, 6, 143, 26}
  #    where we stringify
  #    - domain and 
  #    - data (which might be an address tuple, 'domain name', {pref, 'domain name'} etc ...
  #  and put all that in an easy map:
  #  %{ rcode => int,
  #     ncode => String.t  (see https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)
  #     domain => String.t
  #     ttl => integer
  #     expires => ttl + now()
  #     class => :class
  #     type => :type
  #     data => {int, String.t} | String.t | ...
  #   }
  # - Note that in order to fully be able to use the testcases from
  #
  # DNS cache
  # {domain, type} -> [{:error, reason}] | [{:ok, :nodata}] | [rrdata, rrdata, ..]
  #
  # - Cache & Timeout
  #   If http://www.open-spf.org/svn/project/test-suite/ (the rfc7208 suite) is
  #   to be used to its fullest extend, the cache needs to be able to handle 
  #   TTL's and timeout's of a DNS server.
  #   
  @doc """
  Resolves a query and returns an `ok/error` tuple with the results.

  Returns:
  - `{:error, reason}` if a DNS error occurred
  - `{:ok, []}` if there are ZERO answers
  - `{:ok, [rrs]}` otherwise, where rrs is a list of rrdata's

  """
  @spec resolve(map, binary, atom) :: {map, any}
  def resolve(ctx, name, type \\ :a) when is_map(ctx) and is_binary(name) do
    case from_cache(ctx, name, type) do
      {:error, :cache_miss} ->
        query(ctx, name, type)

      {:error, reason} ->
        # TODO: limit reason to :nxdomain or :zero_answers in order to tick num_dnsv
        {tick(ctx, :num_dnsq)
         |> tick(:num_dnsv)
         |> log(
           :dns,
           :info,
           "DNS QUERY (#{ctx.num_dnsq}) (cached) #{type} #{name} -> #{inspect(reason)}"
         ), {:error, reason}}

      {:ok, res} ->
        {tick(ctx, :num_dnsq)
         |> log(
           :dns,
           :info,
           "DNS QUERY (#{ctx.num_dnsq}) (cached) #{type} #{name} -> #{inspect(res)}"
         ), {:ok, res}}
    end
  end

  defp query(ctx, name, type) do
    # returns either {ctx, {:error, reason}} or {ctx, {:ok, [rrs]}}
    ctx =
      name
      |> String.to_charlist()
      |> :inet_res.resolve(:in, type, [{:timeout, ctx.dns_timeout}])
      |> entries()
      |> cache(ctx, name, type)
      |> tick(:num_dnsq)

    case from_cache(ctx, name, type) do
      # :anlist did not contain an answer for given `type`
      {:error, :cache_miss} ->
        {cache({:error, :zero_answers}, ctx, name, type), {:error, :zero_answers}}

      # :anlist was empty all together
      {:error, reason} ->
        {ctx, {:error, reason}}

      {:ok, res} ->
        {ctx, {:ok, res}}
    end

    # {ctx, from_cache(ctx, name, type)}
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

  defp entries(msg) do
    # return either: {:ok, [{domain, type, value}, ...]} | {:error, reason}
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
    # {:dns_rr, :domain, :type, :in, _, _, :data, :undefined, [], false}
    # -> {domain, type, data}, where shape of data depends on type
    # .e.g :mx -> {10, name}, :a -> {1, 1, 1, 1}, etc ..
    domain = :inet_dns.rr(answer, :domain) |> stringify()
    type = :inet_dns.rr(answer, :type)
    data = :inet_dns.rr(answer, :data) |> stringify(type)
    {domain, type, data}
  end

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

    case ctx.dns[{name, type}] do
      nil -> {:error, :cache_miss}
      [{:error, reason}] -> {:error, reason}
      res -> {:ok, res}
    end
  end

  defp cname(ctx, name, seen \\ %{}) do
    # return canonical name if present, name otherwise, must follow CNAME's
    name = stringify(name) |> String.trim() |> String.trim(".")

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

  # cache an {:error, reason} or data entry for given `name` and `type`
  # note that `name` and `type` come from the {:dns_rr, ..}-record itself.
  defp cache({:error, :nxdomain} = result, ctx, name, type) do
    tick(ctx, :num_dnsv)
    |> log(:dns, :warn, "DNS QUERY (#{ctx.num_dnsq}) #{type} #{name} -> NXDOMAIN")
    |> update({name, type, result})
  end

  defp cache({:error, :zero_answers} = result, ctx, name, type) do
    tick(ctx, :num_dnsv)
    |> log(:dns, :warn, "DNS QUERY (#{ctx.num_dnsq}) #{type} #{name} -> ZERO answers")
    |> update({name, type, result})
  end

  defp cache({:error, :timeout} = result, ctx, name, type) do
    log(ctx, :dns, :warn, "DNS QUERY (#{ctx.num_dnsq}) #{type} #{name} -> TIMEOUT")
    |> update({name, type, result})
  end

  defp cache({:error, {:servfail, _}} = _result, ctx, name, type) do
    log(ctx, :dns, :warn, "DNS QUERY (#{ctx.num_dnsq}) #{type} #{name} -> SERVFAIL")
    |> update({name, type, {:error, :servfail}})
  end

  defp cache({:error, reason} = result, ctx, name, type) do
    # catch all other :error reasons
    log(
      ctx,
      :dns,
      :warn,
      "DNS QUERY (#{ctx.num_dnsq}) #{type} #{name} -> #{inspect(reason)}"
    )
    |> update({name, type, result})
  end

  defp cache({:ok, []}, ctx, name, type) do
    # :inet_resolve might yield an empty :anlist
    tick(ctx, :num_dnsv)
    |> log(:dns, :info, "DNS QUERY (#{ctx.num_dnsq}) #{type} #{name} - ZERO answers")
    |> update({name, type, {:error, :zero_answers}})
  end

  defp cache({:ok, entries}, ctx, name, type) do
    # got some real :dns_rr data records (even if its only CNAME's)
    name = String.trim(name) |> String.trim(".")

    Enum.reduce(entries, ctx, fn entry, acc -> update(acc, entry) end)
    |> log(:dns, :info, "DNS QUERY (#{ctx.num_dnsq}): #{type} #{name} -> #{inspect(entries)}")
  end

  defp update(ctx, {domain, type, data}) do
    # return ctx after updating ctx.dns if appropiate
    # note:
    # - donot use from_cache since that unrolls cnames
    domain = stringify(domain) |> String.trim() |> String.trim(".")
    cached = ctx.dns[{domain, type}] || []
    data = stringify(data, type)

    case data in cached do
      true -> ctx
      false -> Map.put(ctx, :dns, Map.put(ctx.dns, {domain, type}, [data | cached]))
    end
  end

  # stringify -> turn any charlists *inside* rrdata into a string.
  # note:
  # - empty list should turn into {:error, :zero_answers}, and NOT ""
  # - {:error, _} should stay an error-tuple
  defp stringify([]),
    do: {:error, :zero_answers}

  defp stringify(rrdata) when is_list(rrdata) do
    # turn a single (non-empty) charlist or list of charlists into single string
    # this glues the strings together without spaces.
    IO.iodata_to_binary(rrdata)
  end

  defp stringify(rrdata) do
    # catch all, keep it as it is
    rrdata
  end

  # no charlist in error situations
  defp stringify({:error, reason}, _),
    do: {:error, reason}

  # mta name to string
  defp stringify({pref, domain}, :mx),
    do: {pref, stringify(domain)}

  # txt value to string
  defp stringify(txt, :txt) do
    stringify(txt)
  end

  # domain name of ptr record to string
  defp stringify(domain, :ptr),
    do: stringify(domain)

  # address tuple to string (or keep {:error,_}-tuple)
  defp stringify(ip, :a) do
    "#{Pfx.new(ip)}"
  rescue
    _ -> ip
  end

  # address tuple to string (or keep {:error,_}-tuple)
  defp stringify(ip, :aaaa) do
    "#{Pfx.new(ip)}"
  rescue
    _ -> ip
  end

  # primary nameserver and admin contact to string
  defp stringify({mname, rname, serial, refresh, retry, expiry, min_ttl}, :soa),
    do: {stringify(mname), stringify(rname), serial, refresh, retry, expiry, min_ttl}

  defp stringify(data, _) when is_list(data),
    do: stringify(data)

  defp stringify(data, _),
    do: data

  @doc """
  Return all acquired DNS RR's in a flat list of printable lines.

  Note that RR's with multiple entries in their rrdata are listed individually,
  so the output can be copy/paste'd into a local dns.txt pre-cache to facilitate
  experimentation with RR records.

  """
  def to_list(ctx, opts \\ []) do
    valid = Keyword.get(opts, :valid, true)

    ctx.dns
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

  defp rr_tostr(domain, type, data) do
    domain = String.pad_trailing(domain, 25)
    rrtype = String.upcase("#{type}") |> String.pad_trailing(7)
    data = rr_data_tostr(type, data)
    Enum.join([domain, rrtype, data], " ")
  end

  @spec rr_data_tostr(atom, any) :: String.t()
  defp rr_data_tostr(_, {:error, _} = error),
    do: "#{inspect(error)}"

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
