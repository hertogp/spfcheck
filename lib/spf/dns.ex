defmodule Spf.DNS do
  @moduledoc ~S"""
  A simple DNS caching resolver for SPF evaluations.

  During an SPF evaluation all DNS responses are cached.  Since the cache lasts
  only for the duration of the evaluation, TTL values are ignored. The cache
  allows for reporting on DNS data acquired during the evaluation. By
  preloading the cache, using `Spf.DNS.load/2`, new records can be tested.

  The caching resolver also tracks the number of DNS queries made and the
  number of void queries seen.

  ## Example

      iex> zonedata = "
      ...> example.com TXT v=spf1 +all
      ...> "
      iex> ctx = Spf.Context.new("example.com", dns: zonedata)
      iex> {_ctx, result} = Spf.DNS.resolve(ctx, "example.com", type: :txt)
      iex> result
      {:ok, ["v=spf1 +all"]}

  """

  import Spf.Context

  @ldh Enum.concat([?a..?z, [?-], ?0..?9, ?A..?Z])

  @rrtypes %{
    "a" => :a,
    "aaaa" => :aaaa,
    "cname" => :cname,
    "mx" => :mx,
    "ns" => :ns,
    "ptr" => :ptr,
    "soa" => :soa,
    "spf" => :spf,
    "txt" => :txt
  }

  @rgxtypes ~r/\s+(A|AAAA|CNAME|MX|NS|PTR|SOA|SPF|TXT)\s+/i

  @rrerrors %{
    "formerr" => :formerr,
    "nxdomain" => :nxdomain,
    "servfail" => :servfail,
    "timeout" => :timeout,
    "zero_answers" => :zero_answers
  }

  @typedoc """
  A DNS result in the form of an ok/error-tuple.

  In case of succes, this is a list of
  [`dns_data()`](https://www.erlang.org/doc/man/inet_res.html#type-dns_data)
  that is normalized (e.g. charlists are converted to strings as are ip address
  tuples).  Interpretation by caller depends on the `rrtype` used.

  """
  @type dns_result :: {:ok, [any]} | {:error, atom}

  @typedoc """
  An opaque datastructure as returned by `:inet_res.resolve/3` as part of its
  response.

  Interpretation is done using the (erlang internal) `:inet_dns` functions.

  """
  @type dns_msg :: any

  @typedoc """
  An `rrtype` denoted by an atom.

  See also
  [`inet_res.rr_type`](https://www.erlang.org/doc/man/inet_res.html#type-rr_type).

  """
  @type rrtype :: atom

  @typedoc """
  A `domain` is a simply an ascii binary.
  """
  @type domain :: binary

  @typedoc """
  A dns result as returned by `:inet_res.resolve/3`.

  """
  @type res_result :: {:ok, dns_msg} | {:error, any}

  # see also:
  # - https://www.rfc-editor.org/rfc/rfc6895.html
  # - https://erlang.org/doc/man/inet_res.html
  #
  # local cache is map: {domain, type} -> dns_result()

  # API

  @doc """
  Finds a domain `name`'s start of authority and contact.

  SPF evaluation might require evaluating multiple records of different
  domains.  This function allows for reporting the owner and contact for each
  SPF record encountered.

  Returns
  - `{:ok, domain, authority, contact}`, or
  - `{:error, reason}`

  The given `name` does not need to actually exist, the aim is to find the
  owner of the zone the `name` belongs to.  Note that CNAME's are ignored.

  This function should be used *after* evaluation has completed, since it may
  cause void DNS responses. The soa-record is searched by querying for the
  soa-record and dropping the front-label (possibly mulitple times) while
  trying again.

  ## Examples

      iex> Spf.Context.new("example.com")
      ...> |> Spf.DNS.authority("non-existing.example.com")
      {:ok, "non-existing.example.com", "example.com", "noc@dns.icann.org"}

      iex> zonedata = "
      ...> www.example.com CNAME example.org
      ...> "
      iex> Spf.Context.new("some.tld", dns: zonedata)
      ...> |> Spf.DNS.authority("www.example.com")
      {:ok, "www.example.com", "example.com", "noc@dns.icann.org"}

  """
  @spec authority(Spf.Context.t(), binary) :: {:ok, domain, domain, binary} | {:error, atom}
  def authority(ctx, name) do
    labels = normalize(name) |> String.split(".", trim: true)

    # note: since a zone might be delegated, search needs to start with the
    # full domain and drops labels as search continues for the soa record
    for d <- 0..(length(labels) - 2) do
      Enum.drop(labels, d) |> Enum.join(".")
    end
    |> authorityp(ctx)
    |> case do
      {:ok, domain, contact} -> {:ok, name, domain, contact}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Checks validity of a domain name and returns `{:ok, name}` or `{:error, reason}`

  Given `domain` can be a binary or a charlist.  It is normalized (downcase'd,
  trailing dot removed and, if applicable, charlist is converted to a binary)
  and checked that it:

  - is an ascii string
  - is less than 254 chars long
  - has labels that are 1..63 chars long
  - has no empty labels
  - has at least 2 labels
  - has a valid ldh-toplabel

  ## Examples

      iex> check_domain("com")
      {:error, "not multi-label"}

      iex> check_domain(".example.com")
      {:error, "empty label"}

      iex> check_domain("example..com")
      {:error, "empty label"}

      iex> check_domain(<<128>> <> ".com")
      {:error, "contains non-ascii characters"}

      iex> check_domain("example.-com")
      {:error, "tld starts with hyphen"}

      iex> check_domain("example.com-")
      {:error, "tld ends with hyphen"}

      iex> check_domain("example.c%m")
      {:error, "tld not ldh"}

      # trailing dot is dropped
      iex> check_domain("example.c0m.")
      {:ok, "example.c0m"}

      # returned as lowercase binary without the trailing dot
      iex> check_domain('example.COM.')
      {:ok, "example.com"}

  """
  @spec check_domain(binary) :: {:ok, domain} | {:error, binary}
  def check_domain(domain) do
    domain = normalize(domain)
    lbs = String.split(domain, ".")
    tld = List.last(lbs)

    cond do
      String.length(domain) > 253 ->
        {:error, "domain name too long"}

      length(lbs) < 2 ->
        {:error, "not multi-label"}

      Enum.any?(lbs, fn l -> String.length(l) > 63 end) ->
        {:error, "label too long"}

      Enum.any?(lbs, fn l -> String.length(l) < 1 end) ->
        {:error, "empty label"}

      domain != for(<<c <- domain>>, c < 128, into: "", do: <<c>>) ->
        {:error, "contains non-ascii characters"}

      String.starts_with?(tld, "-") ->
        {:error, "tld starts with hyphen"}

      String.ends_with?(tld, "-") ->
        {:error, "tld ends with hyphen"}

      tld == for(<<c <- tld>>, c in ?0..?9, into: "", do: <<c>>) ->
        {:error, "tld all numeric"}

      tld != for(<<c <- tld>>, c in @ldh, into: "", do: <<c>>) ->
        {:error, "tld not ldh"}

      true ->
        {:ok, domain}
    end
  end

  @doc """
  Returns an updated context, a normalized name and a cache result in a 3-tuple

  The cache result can be one of:
  - `{:error, reason}`
  - `{:ok, rrs}`, for a cache hit (where `rrs` is a list of rrdata's).

  Where `reason` includes:
  - `:cache_miss`, nothing found in the cache
  - `:nxdomain`, a previously cached result
  - `:servfail`, a previously cached result or a cname loop was found
  - `:timeout`, a previously cached result
  - `:zero_answers`, a previously cached result
  - `:illegal_name`, name was not a proper domain name

  Note that this function does not make any real DNS requests and does not
  update any dns counters.  The only time the context is updated is when there
  was an error in either `domain` or the `t:rrtype/0` given.

  ## Example

      iex> zonedata = "
      ...> example.net CNAME example.com
      ...> EXAMPLE.COM. A 1.2.3.4
      ...> "
      iex> {_ctx, result} = Spf.Context.new("some.domain.tld", dns: zonedata)
      ...> |> Spf.DNS.from_cache("example.net", :a)
      iex> result
      {:ok, ["1.2.3.4"]}

  """
  @spec from_cache(Spf.Context.t(), domain, rrtype) :: {Spf.Context.t(), dns_result()}
  def from_cache(context, name, type) do
    with {:ok, name} <- check_domain(name),
         {context, {:ok, name}} <- cname(context, name, type) do
      case context.dns[{name, type}] do
        nil -> {context, {:error, :cache_miss}}
        [{:error, reason}] -> {context, {:error, reason}}
        result -> {context, {:ok, result}}
      end
    else
      {:error, reason} -> {log(context, :dns, :error, "#{reason}"), {:error, :illegal_name}}
      {context, {:error, reason}} -> {context, {:error, reason}}
    end
  end

  @doc """
  Filters the `t:dns_result/0`, keeps only the rrdata's for which `fun` returns
  a truthy value.

  If the `dns_result` is actually an error, it is returned untouched.

  ## Examples

      iex> zonedata = "
      ...> example.com TXT v=spf1 -all
      ...> example.com TXT another txt record
      ...> "
      iex> ctx = Spf.Context.new("example.com", dns: zonedata)
      iex> {_ctx, dns_result} = resolve(ctx, "example.com", type: :txt)
      iex>
      iex> dns_result
      {:ok, ["another txt record", "v=spf1 -all"]}
      iex>
      iex> filter(dns_result, &Spf.Eval.spf?/1)
      {:ok, ["v=spf1 -all"]}

      iex> dns_result = {:error, :nxdomain}
      iex> Spf.DNS.filter(dns_result, &Spf.Eval.spf?/1)
      {:error, :nxdomain}

  """
  @spec filter(dns_result(), function()) :: dns_result()
  def filter(dns_result, fun)

  def filter({:ok, rrdatas}, fun),
    do: filter(rrdatas, fun)

  def filter({:error, {reason, _dns_msg}}, _fun),
    # just in case the DNS result was directly supplied by inet_res.resolve
    # rather than Spf.DNS.resolve ...
    do: {:error, reason}

  def filter({:error, reason}, _fun),
    do: {:error, reason}

  def filter(rrdatas, fun) when is_function(fun, 1),
    do: {:ok, Enum.filter(rrdatas, fn rrdata -> fun.(rrdata) end)}

  @doc """
  Populates the dns cache of given `context`, with `dns`'s zonedata.

  `dns` can be a path to an existing file, a multi-line binary containing
  individual RR-records per line or a list thereof. The cache is held in the
  SPF evaluation `context` under the `:dns` key and is a simple map: `{name,
  rrtype}` -> `[rdata]`.

  Lines should be formatted as
  - `name  rrtype  rdata`, or
  - `name  rrtype  error`

  where
  - `rrtype` is one of: #{inspect(Map.keys(@rrtypes))}
  - `error` is one of #{inspect(Map.keys(@rrerrors))}
  - `rdata` text representation of data suitable for given `rrtype`

  Unknown rr-types or otherwise malformed RR's are ignored and logged as a
  warning during preloading.

  It is possible to load zonedata multiple times, each one adds to the cache.
  Note that when setting errors, they always override other similar RR's
  regardless of ordering.

  ## Examples

      iex> zonedata = "
      ...> example.com TXT v=spf1 +all
      ...> example.com A timeout
      ...> EXAMPLE.NET AAAA servfail
      ...> "
      iex> ctx = Spf.Context.new("some.domain.tld")
      ...> |> Spf.DNS.load(zonedata)
      iex>
      iex> {_ctx, result} = Spf.DNS.resolve(ctx, "example.com", type: :txt)
      iex> result
      {:ok, ["v=spf1 +all"]}
      iex>
      iex> Spf.DNS.resolve(ctx, "example.com", type: :a) |> elem(1)
      {:error, :timeout}
      iex>
      iex> Spf.DNS.resolve(ctx, "example.net", type: :aaaa) |> elem(1)
      {:error, :servfail}
      iex>
      iex> ctx.dns
      %{{"example.com", :a} => [error: :timeout],
        {"example.com", :txt} => ["v=spf1 +all"],
        {"example.net", :aaaa} => [error: :servfail]
      }

      iex> zonedata1 = "
      ...> example.com A 1.2.3.4
      ...> example.com A timeout
      ...> example.net A 9.10.11.12
      ...> "
      iex> zonedata2 = "
      ...> example.com AAAA servfail
      ...> example.com AAAA acdc:1976::1
      ...> example.net A 5.6.7.8
      ...> example.net A 9.10.11.12
      ...> "
      iex> ctx = Spf.Context.new("some.tld")
      ...> |> Spf.DNS.load(zonedata1)
      ...> |> Spf.DNS.load(zonedata2)
      iex> ctx.dns[{"example.com", :a}]
      [{:error, :timeout}]
      iex> ctx.dns[{"example.com", :aaaa}]
      [{:error, :servfail}]
      iex> ctx.dns[{"example.net", :a}]
      ["5.6.7.8", "9.10.11.12"]

  """
  @spec load(Spf.Context.t(), nil | binary | [binary]) :: Spf.Context.t()
  def load(context, dns)

  def load(ctx, nil),
    do: ctx

  def load(ctx, dns) do
    case File.exists?(dns) do
      true -> load_file(ctx, dns)
      false -> load_zonedata(ctx, dns)
    end
  end

  @doc """
  Normalize a domain name by trimming, downcasing and removing any trailing
  dot.

  The validity of the domain name is *not* checked.

  ## Examples

      iex> normalize("Example.COM.")
      "example.com"

      iex> normalize("EXAMPLE.C%M")
      "example.c%m"

  """
  @spec normalize(domain | charlist) :: binary
  def normalize(domain) when is_binary(domain) do
    domain
    |> String.trim()
    |> String.replace(~r/\.$/, "")
    |> String.downcase()
  end

  def normalize(domain) when is_list(domain),
    do: List.to_string(domain) |> normalize()

  @doc """
  Resolves a query, updates the cache and returns a {`ctx`,
  `t:dns_result/0`}-tuple.

  Returns one of:
  - `{ctx, {:error, reason}}` if a DNS error occurred or was cached earlier
  - `{ctx, {:ok, [rrs]}}` where rrs is a list of rrdata's

  Although a result with ZERO answers is technically not a DNS error, it
  will be reported as an error.  Error reasons include:
  - `:zero_answers`
  - `:illegal_name`
  - `:timeout`
  - `:nxdomain`
  - `:servfail`
  - other

  Options include:
  - `type:`, which defaults to `:a`
  - `stats`, which defaults to `true`

  When `stats` is `false`, void DNS responses (`:nxdomain` or `:zero_answers`)
  are not counted.

  """
  @spec resolve(Spf.Context.t(), domain, Keyword.t()) :: {Spf.Context.t(), dns_result}
  def resolve(ctx, name, opts \\ []) do
    stats = Keyword.get(opts, :stats, true)
    type = Keyword.get(opts, :type, Map.get(ctx, :atype, :a))

    case from_cache(ctx, name, type) do
      # note that from_cache may return {ctx, {:error, :illegal_name}}
      {ctx, {:error, :cache_miss}} ->
        # cache miss and a legal name here
        tick(ctx, :num_dnsq)
        |> query(name, type, stats)

      {ctx, result} ->
        # either positive result, or {:error, :illegal_name}
        tick(ctx, :num_dnsq)
        |> do_stats(name, type, result, stats, cached: true)
    end
  end

  @doc ~S"""
  Return all acquired DNS RR's in a flat list of printable lines.

  Note that RR's with multiple entries in their rrdata are listed individually,
  so the output can be copy/paste'd into a local dns.txt pre-cache to
  facilitate experimentation with RR records.

  The lines are sorted such that domains and subdomains are kept together as
  much as possible.

  ## Example

      iex> zonedata = "
      ...> example.com TXT v=spf1 -all
      ...> a.example.com A 1.2.3.4
      ...> b.example.com AaAa timeout
      ...> "
      iex> ctx = Spf.Context.new("example.com", dns: zonedata)
      iex> Spf.DNS.to_list(ctx)
      ...> |> Enum.map(fn x -> String.replace(x, ~r/\s+/, " ") end)
      [
        "example.com TXT \"v=spf1 -all\"",
        "a.example.com A 1.2.3.4",
        "b.example.com AAAA TIMEOUT"
      ]
      iex> to_list(ctx, valid: :true)
      ...> |> Enum.map(fn x -> String.replace(x, ~r/\s+/, " ") end)
      [
        "example.com TXT \"v=spf1 -all\"",
        "a.example.com A 1.2.3.4"
      ]
      iex> to_list(ctx, valid: false)
      ...> |> Enum.map(fn x -> String.replace(x, ~r/\s+/, " ") end)
      [
        "b.example.com AAAA TIMEOUT"
      ]

  """
  @spec to_list(Spf.Context.t(), Keyword.t()) :: [binary]
  def to_list(ctx, opts \\ []) do
    keep =
      case Keyword.get(opts, :valid, :both) do
        false -> fn x -> rr_is_error(x) end
        true -> fn x -> not rr_is_error(x) end
        _ -> fn _ -> true end
      end

    Map.get(ctx, :dns, %{})
    |> Enum.map(fn entry -> rr_flatten(entry) end)
    |> List.flatten()
    |> rrs_sort()
    |> Enum.filter(fn {_domain, _type, data} -> keep.(data) end)
    |> Enum.map(fn {domain, type, data} -> rr_encode(domain, type, data) end)
  end

  # Helpers

  @spec authorityp([binary], Spf.Context.t()) :: {:error, atom} | {:ok, domain, binary}
  defp authorityp([], _ctx), do: {:error, :nxdomain}

  defp authorityp([head | tail], ctx) do
    # note: checks ctx.dns-cache directly for {`head`, :soa} skipping CNAME's
    {ctx, _} = resolve(ctx, head, type: :soa)

    case ctx.dns[{head, :soa}] do
      [{_, contact, _, _, _, _, _}] ->
        {:ok, head, String.replace(contact, ".", "@", global: false)}

      _ ->
        authorityp(tail, ctx)
    end
  end

  @spec do_stats(Spf.Context.t(), domain, rrtype, dns_result, boolean, Keyword.t()) ::
          {Spf.Context.t(), dns_result}
  defp do_stats(ctx, name, type, result, stats, opts \\ []) do
    # log any warnings, possibly update void stats & return {ctx, result}
    # note: num_dnsq is updated in resolve, not here
    qry =
      case Keyword.get(opts, :cached, false) do
        true -> "DNS QUERY (#{ctx.num_dnsq}) [cache] #{type} #{name}"
        false -> "DNS QUERY (#{ctx.num_dnsq}) #{type} #{name}"
      end

    delta = if stats, do: 1, else: 0

    case result do
      {:error, :zero_answers} ->
        # a previous cache_miss, cached as zero answers
        {tick(ctx, :num_dnsv, delta) |> log(:dns, :warn, "#{qry} - ZERO answers"), result}

      {:error, :nxdomain} ->
        # nxdomain is a void query
        {tick(ctx, :num_dnsv, delta) |> log(:dns, :warn, "#{qry} - NXDOMAIN"), result}

      {:error, reason} ->
        # any other error, like :servfail or :illegal_name
        err = String.upcase("#{inspect(reason)}")

        {log(ctx, :dns, :warn, "#{qry} - #{err}"), result}

      {:ok, res} ->
        {log(ctx, :dns, :info, "#{qry} - #{inspect(res)}"), result}
    end
  end

  @spec query(Spf.Context.t(), binary, atom, boolean) :: {Spf.Context.t(), dns_result}
  defp query(ctx, name, type, stats) do
    # query DNS for name, type
    opts = []
    timeout = Map.get(ctx, :dns_timeout, 2000)
    opts = Keyword.put(opts, :timeout, timeout)

    opts =
      case Map.get(ctx, :nameservers) do
        nil -> opts
        list -> Keyword.put(opts, :nameservers, list)
      end

    # resolve and update the cache with dns_msg received
    ctx =
      name
      |> String.to_charlist()
      |> :inet_res.resolve(:in, type, opts)
      |> to_dns_results()
      |> cache(ctx, name, type)

    # get result (or not) from cache
    {ctx, result} =
      case from_cache(ctx, name, type) do
        {ctx, {:error, :cache_miss}} -> {ctx, {:error, :zero_answers}}
        {ctx, result} -> {ctx, result}
      end

    do_stats(ctx, name, type, result, stats)
  rescue
    # query should never see illegal names (like example..com), so donot
    # worry about inet_res.resolve() raising FunctionClauseError because
    # it cannot encode the domain name's labels.

    x in CaseClauseError ->
      error = {:error, :unknown_rr_type}

      ctx =
        update(ctx, {name, type, error})
        |> log(:dns, :error, "DNS error: #{name} #{type}: #{inspect(x)}")

      {ctx, error}
  end

  # DNS->CACHE

  @spec to_dns_results(dns_msg) :: dns_result
  defp to_dns_results(msg) do
    # given a dns_msg {:dns_rec, ...} or error-tuple
    # -> return either: {:ok, [{domain, type, value}, ...]} | {:error, reason}
    # notes:
    # - in an `anlist`, each rrdata in the set has its own rrtype
    # - this happens e.g. when resolving for :A and you get :CNAME + :A back
    with {:ok, record} <- msg,
         answers <- :inet_dns.msg(record, :anlist) do
      rrdatas =
        for answer <- answers do
          domain = :inet_dns.rr(answer, :domain) |> to_string()
          type = :inet_dns.rr(answer, :type)
          data = :inet_dns.rr(answer, :data) |> charlists_tostr(type)
          {domain, type, data}
        end

      {:ok, rrdatas}
    end
  end

  @spec cname(Spf.Context.t(), domain, rrtype, map) :: {Spf.Context.t(), {:ok | :error, any}}
  defp cname(ctx, name, type, seen \\ %{})

  defp cname(ctx, name, :cname, _),
    do: {ctx, {:ok, name}}

  defp cname(ctx, name, type, seen) do
    # return canonical name if present, name otherwise, must follow CNAME's
    if seen[name] do
      ctx = log(ctx, :dns, :error, "DNS SERVFAIL - circular CNAMEs: #{inspect(Map.keys(seen))}")

      {ctx, {:error, :servfail}}
    else
      case ctx.dns[{name, :cname}] do
        nil -> {ctx, {:ok, name}}
        [{:error, reason}] -> {ctx, {:error, reason}}
        [realname] -> cname(ctx, realname, type, Map.put(seen, name, realname))
      end
    end
  end

  # from: https://www.erlang.org/doc/man/inet_res.html
  # inet_res.resolve results are one of:
  # a) {:ok, dns_msg()}
  # b) {:error, Reason}, or
  # c) {:error, {Reason, dns_msg()}}
  #
  # where Reason = inet:posix() | res_error()
  # - inet:posix() = an atom named from the POSIX error codes used in Unix
  # - res_error() = formerr, qfmterror, servfail, nxdomain, notimp, refused, badvers, timeout
  #
  # cache stores either
  # - {name, type} -> {:error, :err_code}, or
  # - {name, type} -> [rrdata]

  @spec cache(dns_result, Spf.Context.t(), binary, rrtype) :: Spf.Context.t()
  defp cache({:error, reason}, ctx, name, type),
    do: update(ctx, {name, type, {:error, reason}})

  defp cache({:ok, []}, ctx, name, type),
    do: update(ctx, {name, type, {:error, :zero_answers}})

  defp cache({:ok, entries}, ctx, _name, _type),
    do: Enum.reduce(entries, ctx, fn entry, acc -> update(acc, entry) end)

  @spec update(Spf.Context.t(), {binary, rrtype, any}) :: Spf.Context.t()
  defp update(ctx, {domain, type, {:error, reason}}) do
    error =
      case reason do
        {error_type, _} -> {:error, error_type}
        reason -> {:error, reason}
      end

    Map.put(ctx, :dns, Map.put(ctx.dns, {domain, type}, [error]))
    |> log(:dns, :debug, "added {#{domain}, #{type} -> #{inspect(error)}")
  end

  defp update(ctx, {domain, type, data}) do
    # update the cache for a single entry
    # - donot use from_cache since that unrolls cnames
    cache = Map.get(ctx, :dns, %{})
    domain = normalize(domain)
    cached = cache[{domain, type}] || []
    data = charlists_tostr(data, type)

    case data in cached do
      true ->
        ctx

      false ->
        Map.put(ctx, :dns, Map.put(cache, {domain, type}, [data | cached]))
        |> log(:dns, :debug, "added {#{domain}, #{type}} -> #{inspect(data)}")
    end
  end

  # charlists_tostr/2
  # note:
  # - charlists_tostr is called on non-error dns results, since update/2 has
  #   separate func to inserting errors into the cache (it overwrites).
  # - given a single rdata & type, turn its charlists into binaries (if any)
  # - e.g. charlists_tostr('some text record', :txt)
  # - relies on the fact that query is used for SPF related DNS queries
  #   and authority (:soa) queries only.
  #   (so the number of rrtypes to support is limited)

  # :a, :aaaa rdata
  defp charlists_tostr(ip, rrtype) when rrtype in [:a, :aaaa],
    do: "#{Pfx.new(ip)}"

  # :mta name to string
  defp charlists_tostr({pref, domain}, :mx),
    do: {pref, to_string(domain)}

  # soa rdata
  defp charlists_tostr({mname, rname, serial, refresh, retry, expiry, ttl}, :soa),
    do: {to_string(mname), to_string(rname), serial, refresh, retry, expiry, ttl}

  # other rdata, including :txt, :spf, :ptr, :cname, :ns
  defp charlists_tostr(val, type) when type in [:txt, :spf, :ptr, :cname, :ns],
    do: to_string(val)

  # LINES->CACHE

  @spec load_file(Spf.Context.t(), binary) :: Spf.Context.t()
  defp load_file(ctx, fpath) when is_binary(fpath) do
    ctx =
      case File.read(fpath) do
        {:ok, binary} ->
          load_zonedata(ctx, binary)

        {:error, reason} ->
          log(ctx, :dns, :error, "failed to read #{fpath}: #{inspect(reason)}")
      end

    log(ctx, :dns, :debug, "DNS cache has #{map_size(ctx.dns)} entries")
  end

  @spec load_zonedata(Spf.Context.t(), binary | [binary]) :: Spf.Context.t()
  defp load_zonedata(ctx, binary) when is_binary(binary),
    do:
      String.split(binary, "\n", trim: true)
      |> Enum.map(&String.trim/1)
      |> Enum.filter(fn line -> not String.match?(line, ~r/\s*#/) end)
      |> then(fn lines -> load_zonedata(ctx, lines) end)

  defp load_zonedata(ctx, lines) when is_list(lines) do
    {malformed, good} =
      lines
      |> Enum.map(&rr_decode/1)
      |> List.flatten()
      |> Enum.split_with(fn {k, _, _} -> k == :error end)

    {errors, normal} =
      Enum.split_with(good, fn {_, _, v} -> is_tuple(v) and elem(v, 0) == :error end)

    ctx =
      Enum.reduce(malformed, ctx, fn {_, reason, line}, ctx ->
        log(ctx, :dns, :warn, "RR ignored: #{reason} - #{line}")
      end)

    ctx = Enum.reduce(normal, ctx, fn entry, ctx -> update(ctx, entry) end)
    Enum.reduce(errors, ctx, fn error, ctx -> update(ctx, error) end)
  end

  defp rr_decode(line) do
    with [name, type, rdata] <- String.split(line, @rgxtypes, parts: 2, include_captures: true),
         {:ok, name} <- check_domain(name),
         {:ok, type} <- rrtype_decode(type),
         {:ok, rdata} <- rrdata_decode(type, rdata) do
      {name, type, rdata}
    else
      {:error, reason} -> {:error, reason, line}
      _ -> {:error, "malformed RR", line}
    end
  end

  defp rrtype_decode(type),
    do: {:ok, @rrtypes[String.trim(type) |> String.downcase()]}

  defp rrdata_decode(type, rdata) do
    error = String.downcase(rdata)

    case @rrerrors[error] do
      nil -> rrdata_type_decode(type, rdata)
      atom -> {:ok, {:error, atom}}
    end
  end

  # Notes: rrdata_type_decode
  # - lines are split using regex @rgxtypes, so only those types need
  #   to be dealt with.
  defp rrdata_type_decode(type, rdata) when type in [:txt, :spf],
    do: {:ok, no_quotes(rdata)}

  defp rrdata_type_decode(type, rdata) when type in [:a, :aaaa] do
    pfx = Pfx.new(rdata)

    case {type, pfx.maxlen} do
      {:a, 32} -> {:ok, rdata}
      {:aaaa, 128} -> {:ok, String.downcase(rdata)}
    end
  rescue
    _ -> {:error, "illegal address"}
  end

  defp rrdata_type_decode(:mx, rdata) do
    with [pref, name] <- String.split(rdata, ~r/\s+/, parts: 2),
         {:ok, domain} <- check_domain(name),
         {pref, ""} <- Integer.parse(pref) do
      {:ok, {pref, domain}}
    else
      :error -> {:error, "illegal pref"}
      error -> error
    end
  end

  defp rrdata_type_decode(type, rdata) when type in [:ptr, :cname, :ns],
    do: check_domain(rdata)

  defp rrdata_type_decode(:soa, rdata) do
    # ns responsible-name serial refresh retry expire nxdomain-ttl
    with [ns, rn, serial, refresh, retry, expire, ttl] <-
           String.split(rdata, ~r/\s+/, parts: 7),
         {:ok, ns} <- check_domain(ns),
         {:ok, rn} <- check_domain(rn),
         {:serial, {serial, ""}} <- {:serial, Integer.parse(serial)},
         {:refresh, {refresh, ""}} <- {:refresh, Integer.parse(refresh)},
         {:retry, {retry, ""}} <- {:retry, Integer.parse(retry)},
         {:expire, {expire, ""}} <- {:expire, Integer.parse(expire)},
         {:ttl, {ttl, ""}} <- {:ttl, Integer.parse(ttl)} do
      {:ok, {ns, rn, serial, refresh, retry, expire, ttl}}
    else
      {number, :error} -> {:error, "illegal #{number}"}
      error -> error
    end
  end

  # CACHE->LINES

  @spec rr_encode(binary, atom, any) :: binary
  defp rr_encode(domain, type, data) do
    rrtype = String.upcase("#{type}")
    rrdata = rrdata_encode(type, data)
    "#{domain} #{rrtype} #{rrdata}"
  end

  @spec rrdata_encode(rrtype, any) :: binary
  defp rrdata_encode(_, {:error, reason}) do
    "#{inspect(reason)}"
    |> String.upcase()
    |> String.trim_leading(":")
  end

  defp rrdata_encode(type, ip) when type in [:a, :aaaa] do
    "#{Pfx.new(ip)}"
  rescue
    # just in case..
    _ -> ip
  end

  defp rrdata_encode(:mx, {pref, domain}),
    do: "#{pref} #{domain}"

  defp rrdata_encode(:txt, txt),
    do: inspect(txt)

  defp rrdata_encode(:soa, {ns, rn, serial, refresh, retry, expiry, ttl}),
    do: "#{ns} #{rn} #{serial} #{refresh} #{retry} #{expiry} #{ttl}"

  defp rrdata_encode(_type, data),
    do: "#{inspect(data)}" |> no_quotes()

  defp rr_flatten({{domain, type}, rrdatas}),
    do: for(rrdata <- rrdatas, do: {domain, type, rrdata})

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

  @spec no_quotes(binary) :: binary
  defp no_quotes(str) do
    str
    |> String.replace(~r/^\"/, "")
    |> String.replace(~r/\"$/, "")
  end
end
