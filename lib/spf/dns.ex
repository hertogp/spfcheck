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

      iex> zonedata = "example.com TXT v=spf1 +all"
      iex> ctx = Spf.Context.new("example.com", dns: zonedata)
      iex> {_ctx, result} = Spf.DNS.resolve(ctx, "example.com", type: :txt)
      iex> result
      {:ok, ["v=spf1 +all"]}

  """

  import Spf.Context

  @typedoc """
  A DNS result in the form of an ok/error-tuple.
  """
  @type dns_result :: {:ok, [any]} | {:error, atom}

  @type dns_msg :: any

  @typedoc """
  An `{:error, :cache_miss}`-tuple
  """
  @type cache_miss :: {:error, :cache_miss}

  @typedoc """
  An RR type as supported by the cache.
  """
  @type rrtype :: atom
  # TODO: fix so :inet_res.rr_type() can be used
  @type domain :: binary

  ## XXX: :inet_res dns types
  @type res_result :: {:ok, term} | {:error, atom}

  # /XXX

  # upcase last, since we usually check normalized domain names
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

  # See also:
  # - https://www.rfc-editor.org/rfc/rfc6895.html
  # - https://erlang.org/doc/man/inet_res.html
  #
  # Local cache
  # {domain, type} -> nil | [{:error, :reason}] | [rrdata, rrdata, ..]

  # API

  @doc """
  Finds a domain `name`'s start of authority and contact.

  SPF evaluation might require evaluating multiple records of different
  domains.  This function allows for reporting the owner and contact for each
  SPF record encountered. CNAME's are ignored since the goal is to find the
  authoritative zone for a given (sub)domain `name`.

  Returns
  - `{:ok, domain, authority, contact}`, or
  - `{:error, :err_code}`

  The given `name` does not need to actually exist, the aim is to find the
  owner of the domain the `name` belongs to.

  ## Examples

      iex> Spf.Context.new("example.com")
      ...> |> Spf.DNS.authority("non-existing.example.com")
      {:ok, "non-existing.example.com", "example.com", "noc@dns.icann.org"}

  """
  @spec authority(Spf.Context.t(), binary) :: {:ok, domain, domain, binary} | {:error, atom}
  def authority(ctx, name) do
    labels = normalize(name) |> String.split(".", trim: true)

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

  Checks that the domain name:
  - is an ascii string
  - is less than 254 chars long
  - has labels that are 1..63 chars long, and
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

      iex> check_domain("example.c0m.")
      {:ok, "example.c0m"}

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

  Note that this function does not make any real DNS requests.

  ## Example

       iex> zonedata = ["example.net CNAME example.com", "EXAMPLE.COM. A 1.2.3.4"]
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

    #
    # {context, name} = if type == :cname, do: {context, name}, else: cname(context, name)
    # cache = Map.get(context, :dns, %{})

    # case cache[{name, type}] do
    #   nil -> {:error, :cache_miss}
    #   [{:error, reason}] -> {:error, reason}
    #   res -> {:ok, res}
    # end
  end

  @doc """
  Filters the `t:dns_result/0`, keeps only the rrdata's for which `fun` returns
  a truthy value.

  If the `dns_result` is actually an error, it is returned untouched.

  ## Examples

       iex> zonedata = ["example.com TXT v=spf1 -all", "example.com TXT another txt record"]
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
  context under the `:dns` key and is a simple map: `{name, rrtype}` ->
  `[rdata]`.


  Lines should be formatted as
  - `name  rr-type  data`, or
  - `name  rr-type  error`, or
  - `name  error`

  where
  - `rr-type` is `a`, `aaaa`, `cname`, `mx`, `ns`, `ptr`, `soa`, `spf`, or `txt`
  - `error` is `formerr`, `nxdomain`, `servfail`, `timeout` or `zero_answers`

  The third format will set the rdata for given `name` to given `error` for
  all known `rr-type`'s except for CNAME RR-type since autogenerting a CNAME
  would effectively destroy all access to the domain name's records.

  Unknown rr-types are ignored and logged as a warning during preloading.

  ## Example

      iex> zonedata = [
      ...>   "example.com TXT v=spf1 +all",
      ...>   "example.com A timeout",
      ...>   "EXAMPLE.NET servfail"
      ...> ]
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
      iex> Spf.DNS.resolve(ctx, "example.net", type: :a) |> elem(1)
      {:error, :servfail}
      iex>
      iex> ctx.dns
      %{{"example.com", :a} => [error: :timeout],
        {"example.com", :txt} => ["v=spf1 +all"],
        {"example.net", :a} => [error: :servfail],
        {"example.net", :aaaa} => [error: :servfail],
        {"example.net", :mx} => [error: :servfail],
        {"example.net", :ns} => [error: :servfail],
        {"example.net", :ptr} => [error: :servfail],
        {"example.net", :soa} => [error: :servfail],
        {"example.net", :spf} => [error: :servfail],
        {"example.net", :txt} => [error: :servfail]
      }

      # Note the error did not propagate to the CNAME type.

  """
  @spec load(Spf.Context.t(), nil | binary | [binary]) :: Spf.Context.t()
  def load(context, dns)

  def load(ctx, nil),
    do: ctx

  def load(ctx, dns) do
    case File.exists?(dns) do
      true -> load_file(ctx, dns)
      false -> load_lines(ctx, dns)
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

  Returns:
  - `{ctx, {:error, reason}}` if a DNS error occurred, or
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
      {ctx, {:error, :cache_miss}} ->
        tick(ctx, :num_dnsq)
        |> query(name, type, stats)

      {ctx, {:error, :illegal_name}} ->
        {ctx, {:error, :illegal_name}}

      {ctx, result} ->
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

      iex> zonedata = [
      ...> "example.com TXT v=spf1 -all",
      ...> "a.example.com A 1.2.3.4",
      ...> "b.example.com AaAa timeout"
      ...> ] |> Enum.join("\n")
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

    cache = Map.get(ctx, :dns, %{})

    cache
    |> Enum.map(fn {{domain, type}, data} -> rr_flatten(domain, type, data) end)
    |> List.flatten()
    |> rrs_sort()
    |> Enum.filter(fn {_domain, _type, data} -> keep.(data) end)
    |> Enum.map(fn {domain, type, data} -> rr_tostr(domain, type, data) end)
  end

  # Helpers

  @spec authorityp([binary], Spf.Context.t()) :: {:error, atom} | {:ok, binary, binary}
  defp authorityp([], _ctx), do: {:error, :nxdomain}

  defp authorityp([head | tail], ctx) do
    # TODO: have authorityp return ctx as well?
    # check ctx's cache for results for `head` to skip soa of a possible CNAME
    {ctx, _} = resolve(ctx, head, type: :soa)

    case from_cache(ctx, head, :soa) do
      {_ctx, {:ok, [{_, contact, _, _, _, _, _}]}} ->
        {:ok, head, String.replace(contact, ".", "@", global: false)}

      _ ->
        authorityp(tail, ctx)
    end
  end

  @spec do_stats(Spf.Context.t(), domain, rrtype, dns_result, boolean, Keyword.t()) ::
          {Spf.Context.t(), dns_result}
  defp do_stats(ctx, name, type, result, stats, opts \\ []) do
    # log any warnings, possibly update stats & return {ctx, result}
    qry =
      case Keyword.get(opts, :cached, false) do
        true -> "DNS QUERY (#{ctx.num_dnsq}) [cache] #{type} #{name}"
        false -> "DNS QUERY (#{ctx.num_dnsq}) #{type} #{name}"
      end

    delta = if stats, do: 1, else: 0

    case result do
      {:error, :cache_miss} ->
        # result didn't include an answer for given `type`
        result = {:error, :zero_answers}

        {update(ctx, {name, type, result})
         |> tick(:num_dnsv, delta)
         |> log(:dns, :warn, "#{qry} - ZERO answers"), result}

      {:error, :zero_answers} ->
        # zero answers is a void query
        {tick(ctx, :num_dnsv, delta) |> log(:dns, :warn, "#{qry} - ZERO answers"), result}

      {:error, :nxdomain} ->
        # nxdomain is a void query
        {tick(ctx, :num_dnsv, delta) |> log(:dns, :warn, "#{qry} - NXDOMAIN"), result}

      {:error, reason} ->
        # any other error, like :servfail
        err = String.upcase("#{inspect(reason)}")

        {log(ctx, :dns, :warn, "#{qry} - #{err}"), result}

      {:ok, res} ->
        {log(ctx, :dns, :info, "#{qry} - #{inspect(res)}"), result}
    end
  end

  @spec load_file(Spf.Context.t(), binary) :: Spf.Context.t()
  defp load_file(ctx, fpath) when is_binary(fpath) do
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

  @spec load_lines(Spf.Context.t(), [binary] | binary) :: Spf.Context.t()
  defp load_lines(ctx, lines) when is_binary(lines),
    do: load_lines(ctx, String.split(lines, "\n"))

  defp load_lines(ctx, lines) when is_list(lines) do
    lines
    |> Enum.map(&String.trim/1)
    |> Enum.reduce(ctx, &rr_fromstr/2)
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
    x in CaseClauseError ->
      error = {:error, :unknown_rr_type}

      ctx =
        update(ctx, {name, type, error})
        |> log(:dns, :error, "DNS error: #{name} #{type}: #{inspect(x)}")

      {ctx, error}

    x in FunctionClauseError ->
      error = {:error, :illegal_name}

      ctx =
        update(ctx, {name, type, error})
        |> log(:dns, :error, "DNS illegal name: #{name} #{Exception.message(x)}")

      {ctx, error}
  end

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
          domain = :inet_dns.rr(answer, :domain) |> charlists_tostr()
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
    # name = charlists_tostr(name) |> normalize()
    # cache = Map.get(ctx, :dns, %{})

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
  # @spec cache(dns_result, Spf.Context, binary, rrtype) :: Spf.Context.t()
  # defp cache({:error, {reason, _dns_msg}} = _result, ctx, name, type),
  #   do: update(ctx, {name, type, {:error, reason}})

  defp cache({:error, reason}, ctx, name, type),
    do: update(ctx, {name, type, {:error, reason}})

  defp cache({:ok, []}, ctx, name, type),
    do: update(ctx, {name, type, {:error, :zero_answers}})

  defp cache({:ok, entries}, ctx, _name, _type),
    do: Enum.reduce(entries, ctx, fn entry, acc -> update(acc, entry) end)

  defp update(ctx, {domain, type, {:error, _} = error}) do
    Map.put(ctx, :dns, Map.put(ctx.dns, {domain, type}, [error]))
    |> log(:dns, :debug, "added {#{domain}, #{type} -> #{inspect(error)}")
  end

  @spec update(Spf.Context.t(), {binary, rrtype, any}) :: Spf.Context.t()
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

  # charlists_tostr -> normalize rrdata by turning any embedded charlists
  # into string.
  # note:
  # - empty list should turn into {:error, :zero_answers}, and NOT ""
  # - {:error, _} should stay an error-tuple
  # charlists_tostr/1 is helper for charlists_tostr/2
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

  # charlists_tostr/2 for types of rrdatas
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

  # address tuple to string (or keep {:error, _}-tuple)
  defp charlists_tostr(ip, :a) do
    "#{Pfx.new(ip)}"
  rescue
    _ -> ip
  end

  # address tuple to string (or keep {:error, _}-tuple)
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

  defp rr_flatten(domain, type, rrdatas),
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

  @spec rr_fromstr(binary, Spf.Context.t()) :: Spf.Context.t()
  defp rr_fromstr(str, ctx) do
    String.trim(str) |> rr_fromstrp(ctx)
  end

  @spec rr_fromstrp(binary, Spf.Context.t()) :: Spf.Context.t()
  defp rr_fromstrp("#" <> _, ctx),
    # this is why str must be trimmed already
    do: ctx

  defp rr_fromstrp("", ctx),
    do: ctx

  defp rr_fromstrp(str, ctx) do
    case rr_line(str) do
      {:ok, rrs} -> Enum.reduce(rrs, ctx, fn entry, ctx -> only_new(ctx, entry) end)
      {:error, reason} -> Spf.Context.log(ctx, :dns, :warn, "#{reason} -- ignored rr '#{str}'")
    end
  end

  defp only_new(ctx, {name, type, {:error, reason}}) do
    # only add {:error, reason} if there is no existing RR for {name, type}
    # note: assumes rr_line_parts has normalized both `name` and `type`
    case ctx.dns[{name, type}] do
      nil -> update(ctx, {name, type, {:error, reason}})
      _ -> ctx
    end
  end

  defp only_new(ctx, entry),
    do: update(ctx, entry)

  defp rr_line(line) do
    # return {:ok, [{name, type, rdata}] or {:error, reason}
    #
    # :NOTE: rfc7208's tst:13.9 (macro-mania-in-domain) has a space in a domain, hence:
    # - `name type rdata` is tried first for *known* types, if that fails
    # - `name error` is assumed and the line is split on the last word
    # - NEVER autogenerate an error record for CNAME, since that destroys lookups
    split =
      case String.split(line, @rgxtypes, parts: 2, include_captures: true) do
        [name, type, rdata] -> [name, String.trim(type), rdata]
        _ -> String.split(line, ~r/\S+$/, include_captures: true, trim: true)
      end

    alltypes =
      Enum.filter(@rrtypes, fn {_name, type} -> type != :cname end)
      |> Enum.map(fn {name, _type} -> name end)

    case split do
      [name, type, rdata] -> rr_line_parts(name, [type], rdata)
      [name, rdata] -> rr_line_parts(name, alltypes, rdata)
      _ -> {:error, :malformed}
    end
  end

  defp rr_line_parts(name, types, rdata) do
    with {:ok, domain} <- normalize(name) |> check_domain(),
         {:ok, types} <- rr_line_types(types),
         {:ok, data} <- rr_line_data(types, rr_line_unquote(rdata)) do
      {:ok, for(type <- types, do: {domain, type, data})}
    else
      error ->
        if length(types) > 1,
          do: {:error, :malformed_rr},
          else: error
    end
  end

  defp rr_line_types(types) do
    types = Enum.map(types, fn type -> @rrtypes[String.downcase(type)] end)

    case Enum.member?(types, nil) do
      true -> {:error, :unsupported_type}
      false -> {:ok, types}
    end
  end

  defp rr_line_data(_, {:error, error}),
    do: {:ok, {:error, error}}

  defp rr_line_data([type], rdata) when type in [:a, :aaaa] do
    pfx = Pfx.new(rdata)

    case {type, pfx.maxlen} do
      {:a, 32} -> {:ok, rdata}
      {:aaaa, 128} -> {:ok, String.downcase(rdata)}
      _ -> {:error, :einvalid_addr}
    end
  rescue
    _ -> {:error, :einvalid_addr}
  end

  defp rr_line_data([:mx], rdata) do
    with [pref, name] <- String.split(rdata, ~r/\s+/, parts: 2),
         {:ok, domain} <- normalize(name) |> check_domain(),
         {pref, ""} <- Integer.parse(pref) do
      {:ok, {pref, domain}}
    else
      _ -> {:error, :illegal_mx}
    end
  end

  defp rr_line_data([type], rdata) when type in [:ptr, :cname, :ns],
    do: normalize(rdata) |> check_domain()

  defp rr_line_data([type], rdata) when type in [:spf, :txt],
    do: {:ok, no_quotes(rdata)}

  defp rr_line_data([:soa], rdata) do
    # master-name responsible-name serial refresh retry expire nxdomain-ttl
    with [mn, rn, serial, refresh, retry, expire, nxttl] <-
           String.split(rdata, ~r/\s+/, parts: 7),
         {:ok, mn} <- normalize(mn) |> check_domain(),
         {:ok, rn} <- normalize(rn) |> check_domain(),
         {serial, ""} <- Integer.parse(serial),
         {refresh, ""} <- Integer.parse(refresh),
         {retry, ""} <- Integer.parse(retry),
         {expire, ""} <- Integer.parse(expire),
         {nxttl, ""} <- Integer.parse(nxttl) do
      {:ok, {mn, rn, serial, refresh, retry, expire, nxttl}}
    else
      _ -> {:error, :illegal_soa}
    end
  end

  defp rr_line_data(_type, _rdata) do
    # either type or rdata is wrong here
    {:error, :unsupported_rr}
  end

  defp rr_line_unquote(rdata) do
    # returns either:
    # - an unquote'd rdata (NOT changing case) or
    # - a known, supported rdata error-tuple
    rdata = no_quotes(rdata)

    case @rrerrors[String.downcase(rdata)] do
      nil -> rdata
      error -> {:error, error}
    end
  end

  @spec rr_tostr(binary, atom, any) :: binary
  defp rr_tostr(domain, type, data) do
    domain = String.pad_trailing(domain, 25) |> String.downcase()
    rrtype = String.upcase("#{type}") |> String.pad_trailing(7)
    data = rr_data_tostr(type, data)
    Enum.join([domain, rrtype, data], " ")
  end

  @spec rr_data_tostr(atom, any) :: binary
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

  @spec no_quotes(binary) :: binary
  defp no_quotes(str) do
    str
    |> String.replace(~r/^\"/, "")
    |> String.replace(~r/\"$/, "")
  end
end
