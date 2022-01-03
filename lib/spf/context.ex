defmodule Spf.Context do
  @moduledoc """
  Functions to create, access and update an SPF evaluation context.

  Many functions take and return an evaluation context whose purpose
  is to store information gathered during the evaluation.  This includes
  a dns cache, an ip lookup table that maps prefixes to SPF terms that
  named them, a stack for recursive evaluations, as well as some statistics
  around DNS mechanisms seen and void DNS responses seen.

  """

  @typedoc """
  An SPF evaluation result.
  """
  @type verdict :: :fail | :neutral | :none | :pass | :permerror | :softfail | :temperror

  @typedoc """
  An SPF evaluation context.

  Field notes:
  - `ast` is a list of SPF terms to be evaluated as produced by `Spf.Parser`
  - `atype` is set according to the sender's IP address
  - `contact` is gleaned from the soa record for `domain` under evaluation
  - `depth` is the nested depth during recursion, used to print a tree of log messages
  - `dns` is the DNS cache, used to report on DNS information gathered during evaluation
  - `duration` is the time (in seconds) it took to evaluate the SPF policy
  - `error` set by either `Spf.Parser` or `Spf.Eval` and halts evaluation if set
  - `explain` is the token for the `exp=`-modifier, if any (not needed for actual evaluation)
  - `explain_string` is the explanation after all expansions (when available and applicable)
  - `helo` as set by the `:helo` option given to `Spf.check/2`
  - `ip` is the sender IP, as set by the `:ip` option given to `Spf.check/2` (default `127.0.0.1`)
  - `ipt` is an `t:Iptrie.t/0` used to record addresses and/or prefixes authorized to send mails
  - `local` is the local part of the `sender`
  - `log` is the user callback log function as provided by the `:log` option to `Spf.check/2`
  - `map` is used to record `nth` => domain and domain => spf-string
  - `max_dnsm` is the max of dns-mechanisms allowed (default 10), if it took more => permerror
  - `max_dnsv` is the max of void dns-responses allowed (default 2), if it took more => permerror
  - `msg` the list of logged messages by the Spf modules
  - `nameservers` a list of nameservers to use or nil (uses system default)
  - `nth` is the nth SPF record being evaluated
  - `num_checks` counts how many checks were performed during evaluation
  - `num_dnsm` counts the number of dns-mechanisms seen during evaluation
  - `num_dnsq` counts the number of dns queries performed during evaluation
  - `num_dnsv` counts the number of void DNS responses seen during evaluation
  - `num_error` counts the number of errors seen during evaluation
  - `num_spf` counts the number of SPF records evaluated
  - `num_warn` counts the number of warnings seen during evaluation
  - `owner` shows the SOA zone for the original SPF domain being evaluated
  - `reason` shows the reason for the verdict, usually in the form of an SPF term
  - `sender` is the sender as given to `Spf.check/2`
  - `spf` is the SPF string of the `domain` being evaluated (if any)
  - `spf_rest` is the remainder of the SPF string (should always by "")
  - `spf_tokens` is the `Spf.Lexer`'s result of lexing the SPF string (last seen)
  - `stack` is used to push/pop the evaluation state during recursive calls
  - `t0` is the Unix Epoch time the evaluation started
  - `traces` is a map used to detect loops in an SPF policy
  - `verbosity` controls the level of logged messages to stderr
  - `verdict` is the final result of the SPF evaluation by `Spf.check/2`

  Other notes:
  - `max_dnsm` and `max_dnsv` are only checked *after* evaluating the entire policy
     - this allows to debug most of the SPF policy under consideration
  - `Spf.Parser` may set an syntax `error`, in which case the SPF record results in a permerror
      - the `ast` is produced by the parser by processing *all* `spf_tokens`
      - whitespace tokens are used to report on repeated whitespace in an SPF string
      - whitespace tokens donot end up in the AST
      - `v=spf1`-modifier is checked and if not present, results in an error
      - by processing all tokens, any `error` set reflects the last error seen
  - `Spf.Eval` may set an evaluation `error`, which *may* result in an overall permerror
  - a void DNS response is either a `NXDOMAIN` or `ZERO ANSWERS`

  """
  @type t :: %{
          :ast => list(),
          :atype => :a | :aaaa,
          :contact => binary(),
          :depth => non_neg_integer(),
          :dns => map(),
          :dns_timeout => non_neg_integer(),
          :domain => binary(),
          :duration => non_neg_integer(),
          :error => nil | atom(),
          :explain => nil | tuple(),
          :explain_string => binary(),
          :explanation => binary(),
          :helo => binary(),
          :ip => binary(),
          :ipt => Iptrie.t(),
          :local => binary(),
          :log => nil | function(),
          :map => map(),
          :max_dnsm => non_neg_integer(),
          :max_dnsv => non_neg_integer(),
          :msg => list(),
          :nameservers => nil | list(),
          :nth => non_neg_integer(),
          :num_checks => non_neg_integer(),
          :num_dnsm => non_neg_integer(),
          :num_dnsq => non_neg_integer(),
          :num_dnsv => non_neg_integer(),
          :num_error => non_neg_integer(),
          :num_spf => non_neg_integer(),
          :num_warn => non_neg_integer(),
          :owner => binary(),
          :reason => binary(),
          :sender => binary(),
          :spf => binary(),
          :spf_rest => binary(),
          :spf_tokens => list(),
          :stack => list(),
          :t0 => non_neg_integer(),
          :traces => map(),
          :verbosity => non_neg_integer(),
          :verdict => verdict()
        }

  @typedoc """
  A `t:Spf.Lexer.token/0`.
  """
  @type token :: Spf.Lexer.token()

  @typedoc """
  A `t:Pfx.prefix/0`.
  """
  @type prefix :: Pfx.prefix()

  @typedoc """
  A `{qualifier, nth, term}` tuple, where `nth` is the nth SPF record where `term` was
  found.

  The context's ip lookup table stores these tuples thus tracking which term in
  which SPF record provided a qualifier for a prefix.  Since an evaluation may
  involve multiple SPF records, each prefix actually stores a list of these
  tuples.

  Once the sender's ip has a longest prefix match, the qualifier will tell how
  the mechanism at hand matches.

  """
  @type iptval :: {Spf.Lexer.q(), non_neg_integer, binary}

  @context %{
    :ast => [],
    :atype => :a,
    :contact => "",
    :depth => 0,
    :dns => %{},
    :dns_timeout => 2000,
    :domain => "",
    :duration => 0,
    :error => nil,
    :explain => nil,
    :explain_string => "",
    :explanation => "",
    :helo => "",
    :ip => "",
    :ipt => Iptrie.new(),
    :local => "",
    :log => nil,
    :map => %{},
    :max_dnsm => 10,
    :max_dnsv => 2,
    :msg => [],
    :nameservers => nil,
    :nth => 0,
    :num_checks => 0,
    :num_dnsm => 0,
    :num_dnsq => 0,
    :num_dnsv => 0,
    :num_error => 0,
    :num_spf => 1,
    :num_warn => 0,
    :owner => "",
    :reason => "",
    :sender => "",
    :spf => "",
    :spf_rest => "",
    :spf_tokens => [],
    :stack => [],
    :t0 => 0,
    :traces => %{},
    :verbosity => 4,
    :verdict => :neutral
  }

  # Helpers

  @spec ipt_values(list, prefix()) :: list
  defp ipt_values(keyvals, k) do
    # filter & turn keyvals [{pfx, [{q, nth, "term"}]}] into [{q, nth, "term"}]
    keyvals
    |> Enum.filter(fn {p, _vals} -> p != k end)
    |> Enum.map(&elem(&1, 1))
    |> List.flatten()
    |> Enum.reverse()
  end

  @spec ipt_update({prefix, iptval}, t) :: t
  defp ipt_update({k, v}, ctx) do
    q = elem(v, 0)
    notq = fn {qq, _, _} -> qq != q end
    # less specific entries (if any)
    less = Iptrie.less(ctx.ipt, k) |> ipt_values(k)
    less_n = length(less)
    less_t = Enum.map(less, &elem(&1, 2)) |> Enum.uniq() |> Enum.join(", ")
    less_q = Enum.map([v | less], &elem(&1, 0)) |> MapSet.new() |> MapSet.size()
    less_i = Enum.filter(less, notq) |> Enum.map(&elem(&1, 2)) |> Enum.join(", ")

    # more specific entries (if any)
    more = Iptrie.more(ctx.ipt, k) |> ipt_values(k)
    more_n = length(more)
    more_t = Enum.map(more, &elem(&1, 2)) |> Enum.uniq() |> Enum.join(", ")
    more_q = Enum.map([v | more], &elem(&1, 0)) |> MapSet.new() |> MapSet.size()
    more_i = Enum.filter(more, notq) |> Enum.map(&elem(&1, 2)) |> Enum.join(", ")

    # same prefix entries (if any) -> [{q, nth, "term"}]
    other = Iptrie.get(ctx.ipt, k, {k, []}) |> elem(1)
    other_n = length(other)
    other_t = Enum.map(other, &elem(&1, 2)) |> Enum.uniq() |> Enum.reverse() |> Enum.join(", ")
    other_q = Enum.map([v | other], &elem(&1, 0)) |> MapSet.new() |> MapSet.size()
    other_i = Enum.filter(other, notq) |> Enum.map(&elem(&1, 2))

    t = elem(v, 2)

    ctx
    |> Map.put(:ipt, Iptrie.put(ctx.ipt, k, [v | other]))
    |> log(:ipt, :debug, "#{t} - adds #{k} -> #{inspect(v)}")
    |> test(:ipt, :warn, other_n > 0, "#{t} - redundant entry, already have: #{other_t}")
    |> test(:ipt, :warn, other_q > 1, "#{t} - inconsistent with #{other_i}")
    |> test(:ipt, :warn, less_n > 0, "#{t} - unreachable due to less specific #{less_t}")
    |> test(:ipt, :warn, less_q > 1, "#{t} - inconsistent with less specific #{less_i}")
    |> test(:ipt, :warn, more_n > 0, "#{t} - overlaps with more specific #{more_t}")
    |> test(:ipt, :warn, more_q > 1, "#{t} - inconsistent with more specific #{more_i}")
  end

  @spec opt_ip(t, Keyword.t()) :: t
  defp opt_ip(ctx, opts) do
    # IPV4-mapped IPv6 addresses are converted to the mapped IPv4 address
    # note: check validity of user supplied IP address, default to 127.0.0.1
    ip = Keyword.get(opts, :ip, "127.0.0.1")

    {ipinvalid, pfx} =
      try do
        {false, Pfx.new(ip)}
      rescue
        ArgumentError -> {true, Pfx.new("127.0.0.1")}
      end

    {xtracted, pfx} =
      case Pfx.member?(pfx, "::FFFF:0:0/96") do
        true -> {true, Pfx.cut(pfx, -1, -32)}
        false -> {false, pfx}
      end

    # atype = if pfx.maxlen == 32 or Pfx.member?(pfx, "::FFFF:0/96"), do: :a, else: :aaaa
    atype = if pfx.maxlen == 32, do: :a, else: :aaaa

    ctx
    |> Map.put(:atype, atype)
    |> Map.put(:ip, "#{pfx}")
    |> log(:ctx, :info, "sender ip is     '#{pfx}'")
    |> test(:ctx, :error, ipinvalid, "ip '#{ip}' is invalid, so using '#{pfx}' instead")
    |> test(:ctx, :note, xtracted, "'#{pfx}' was extracted from IPv4-mapped IPv6 address '#{ip}'")
    |> log(:ctx, :debug, "atype set to '#{atype}'")
  end

  @spec opt_nameserver(t, Keyword.t()) :: t
  defp opt_nameserver(ctx, opts) do
    # pickup any user provided nameserver (if any)
    nameservers =
      Keyword.take(opts, [:nameserver])
      |> Enum.map(fn {_, ip} -> Pfx.parse(ip) end)
      |> Enum.filter(fn {res, _} -> res == :ok end)
      |> Enum.map(fn {_, ip} -> Pfx.marshall(ip, {0, 0, 0, 0}) end)
      |> Enum.map(fn ip -> {ip, 53} end)
      |> case do
        [] -> nil
        list -> list
      end

    ctx
    |> Map.put(:nameservers, nameservers)
    |> test(:ctx, :debug, nameservers != nil, "nameservers set to #{inspect(nameservers)}")
    |> test(:ctx, :debug, nameservers == nil, "nameservers set to default")
  end

  @spec opt_sender(t, binary, Keyword.t()) :: t
  defp opt_sender(ctx, sender, opts) do
    helo = Keyword.get(opts, :helo, sender)
    {local, domain} = split(sender)

    {local, domain} =
      if String.length(domain) < 1,
        do: split(helo),
        else: {local, domain}

    ctx
    |> Map.put(:sender, sender)
    |> Map.put(:local, local)
    |> Map.put(:domain, domain)
    |> Map.put(:helo, helo)
    |> Map.put(:map, %{0 => domain, domain => ""})
    |> log(:ctx, :info, "sender domain is '#{sender}'")
    |> log(:ctx, :info, "sender local  is '#{local}'")
    |> log(:ctx, :info, "spf domain is    '#{domain}'")
    |> log(:ctx, :debug, "helo set to '#{helo}'")
    |> test(:ctx, :debug, helo == sender, "helo defaults to sender value")
  end

  @spec prefix(binary, [non_neg_integer]) :: :error | prefix
  defp prefix(ip, [len4, len6]) do
    pfx = Pfx.new(ip)

    case pfx.maxlen do
      32 -> Pfx.keep(pfx, len4)
      _ -> Pfx.keep(pfx, len6)
    end
  rescue
    _ -> :error
  end

  @spec trace(t, binary) :: t
  defp trace(ctx, new_domain) do
    # called when current domain includes or redirects to new_domain
    cur_domain = String.downcase(ctx.domain)
    new_domain = String.downcase(new_domain)

    # keep track of where domains lead to:
    # - cur_domain -> new_domain
    # - if domain -> cur_domain, then it leads to new_domain also
    upd_trace = fn cur_domain, new_domain, trace ->
      if cur_domain in trace,
        do: [new_domain | trace],
        else: trace
    end

    Map.update(ctx.traces, cur_domain, [new_domain], fn v -> [new_domain | v] end)
    |> Enum.reduce(%{}, fn {domain, trace}, acc ->
      Map.put(acc, domain, upd_trace.(cur_domain, new_domain, trace))
    end)
    |> then(fn traces -> Map.put(ctx, :traces, traces) end)
  end

  # API CONTEXT

  @doc """
  Updates `context.ipt` with one or more {`t:prefix/0`, `t:iptval/0`}-pairs.

  When given a list op ip's, they all will be be updated with given 
  `t:iptval/0` which records the SPF record and term (including the qualifier)
  that attributed the ip or ip's.

  The `dual` parameter contains the dual-cidr lengths to apply to the given
  ip addresses.

  """
  @spec addip(t, list(), list(), iptval) :: t
  def addip(context, ips, dual, value) when is_list(ips) do
    kvs =
      Enum.map(ips, fn ip -> {prefix(ip, dual), value} end)
      |> Enum.filter(fn {k, _v} -> k != :error end)

    Enum.reduce(kvs, context, &ipt_update/2)
  end

  @spec addip(t, binary, list(), iptval) :: t
  def addip(context, ip, dual, value) when is_binary(ip) do
    case prefix(ip, dual) do
      :error -> log(context, :ctx, :error, "ignored malformed IP #{ip}")
      pfx -> ipt_update({pfx, value}, context)
    end
  end

  @doc """
  Updates `context` with given `error`, `reason` and `verdict`.

  When `verdict` is nil, `context.verdict` is not updated.  This
  allows for setting error conditions whose impact is to be evaluated
  at a later stage.

  """
  @spec error(t, atom, atom, binary, nil | atom) :: t
  def error(context, facility, error, reason, verdict \\ nil) do
    Map.put(context, :error, error)
    |> Map.put(:reason, reason)
    |> Map.put(:verdict, verdict || context.verdict)
    |> log(facility, :error, reason)
  end

  @doc """
  Returns a previous SPF string given either its `domain` of `nth`-tracking number.

  Used for reporting rather than evalutation an SPF record.

  """
  @spec get_spf(t, integer | binary) :: binary
  def get_spf(context, nth) when is_integer(nth) do
    with domain when is_binary(domain) <- context.map[nth] do
      get_spf(context, domain)
    else
      _ -> "ERROR SPF[#{nth}] NOT FOUND"
    end
  end

  def get_spf(context, domain) when is_binary(domain) do
    case Spf.DNS.from_cache(context, domain, :txt) do
      {_ctx, {:error, _}} -> "ERROR SPF NOT FOUND"
      {_ctx, {:ok, rrs}} -> Enum.find(rrs, "ERROR SPF NOT FOUND", &Spf.Eval.spf?/1)
    end
  end

  @doc """
  Given a current `context` and a `range`, return the SPF term in that range.

  Retrieves a slice of the current SPF record being evaluated. Used for logging
  events.

  """
  @spec spf_term(t, Range.t()) :: binary
  def spf_term(context, range),
    do: "spf[#{context.nth}] #{String.slice(context.spf, range)}"

  @doc """
  Updates `context`'s message queue and, if available, calls the user supplied log
  function.

  The `log/4` is called with:
  - `context` the current context/state of the evalution
  - `facility` an atom denoting which part of the program emitted the event
  - `severity` an atom describing the severity
  - `msg` a binary with event details

  """
  @spec log(t, atom, atom, binary) :: t
  def log(context, facility, severity, msg) do
    if context[:log],
      do: context.log.(context, facility, severity, msg)

    nth = Map.get(context, :nth, 0)

    context =
      Map.update(context, :msg, [{nth, facility, severity, msg}], fn msgs ->
        [{nth, facility, severity, msg} | msgs]
      end)

    case severity do
      :warn -> tick(context, :num_warn)
      :error -> tick(context, :num_error)
      _ -> context
    end
  end

  @doc """
  Returns true if `new_domain` constitues a loop for given `context`, false
  otherwise.

  Loops may occur when two SPF records (eventually) include or redirect to
  each other and is considered a permanent error.

  """
  @spec loop?(t, binary) :: boolean
  def loop?(context, new_domain) do
    new_domain = String.downcase(new_domain)
    cur_domain = String.downcase(context.domain)
    cur_domain in Map.get(context.traces, new_domain, [])
  end

  @doc """
  Split an email address into a local and a domain part.

  The local part is left to the left-most `@`, if there is no local
  part it defaults to "postmaster".  Note that splitting an empty
  string yields `{"postmaster", ""}`.

  """
  @spec split(binary) :: {binary, binary}
  def split(mbox) do
    words =
      String.replace(mbox, ~r/\.$/, "")
      |> String.split("@", parts: 2, trim: true)

    case words do
      [] -> {"postmaster", ""}
      [local, domain] -> {local, domain}
      [domain] -> {"postmaster", domain}
    end
  end

  @doc """
  Returns a new `t:Spf.Context.t/0` for given `sender`.

  Options include:
  - `:dns`, filepath or binary with zonedata (defaults to nil)
  - `:helo`, sender's helo string to use (defaults to `sender`)
  - `:ip`, sender ip to use (defaults to `127.0.0.1`)
  - `:log`, user supplied log function (defaults to nil)
  - `:verbosity`, log level `0..5` to use (defaults to `4`)
  - `:nameserver`, IPv4 or IPv6 address of a nameserver to use instead of the default

  The initial `domain` is derived from given `sender`.  The default for
  `ip` is likely to traverse all SPF mechanisms during evaluation, gathering
  as much information as possible.  Set `:ip` to a real IPv4 or IPv6 address
  to check an SPF policy for that specific address.

  The context is used for the entire SPF evaluation, including during any
  recursive calls.  When evaluating an `include` mechanism, the current state (a
  few selected context properties) is pushed onto an internal stack and a new
  `domain` is set.  After evaluating the `include` mechanism, the state if
  popped and the results are processed according to the `include`-mechanism's
  qualifier.

  When evaluating a `redirect` modifier, the current state is altered for the
  new domain specified by the modifier.

  Specify more than one recursive nameserver by repeating the `:nameserver`
  option in the Keyword list.  They will be tried in the order listed.  Mainly
  useful when the local default recursive nameserver is having problems, or
  when an external nameserver is to be used for checking an SPF policy instead
  of an internal nameserver.  As an example, use in opts `[nameserver:
  "2001:4860:4860::8888", nameserver: "2001:4860:4860::8844"]` to use the IPv6
  dns.google servers.

  """
  @spec new(binary, Keyword.t()) :: t
  def new(sender, opts \\ []) do
    @context
    |> Map.put(:log, Keyword.get(opts, :log, nil))
    |> Map.put(:verbosity, Keyword.get(opts, :verbosity, 4))
    |> Map.put(:dns_timeout, Keyword.get(opts, :timeout, 2000))
    |> opt_sender(sender, opts)
    |> opt_ip(opts)
    |> opt_nameserver(opts)
    |> Map.put(:t0, System.os_time(:second))
    |> Spf.DNS.load(Keyword.get(opts, :dns, nil))
    |> then(&log(&1, :ctx, :info, "DNS cache preloaded with #{map_size(&1.dns)} entrie(s)"))
    |> then(&log(&1, :ctx, :info, "verbosity level #{&1.verbosity}"))
    |> then(&log(&1, :ctx, :debug, "DNS timeout set to #{&1.dns_timeout}"))
    |> then(&log(&1, :ctx, :debug, "max DNS mechanisms set to #{&1.max_dnsm}"))
    |> then(&log(&1, :ctx, :debug, "max void DNS lookups set to #{&1.max_dnsv}"))
    |> then(&log(&1, :ctx, :debug, "verdict defaults to '#{&1.verdict}'"))
    |> then(&log(&1, :ctx, :info, "created context for '#{&1.domain}'"))
    |> then(&log(&1, :spf, :note, "spfcheck(#{&1.domain}, #{&1.ip}, #{&1.sender})"))
  end

  @doc """
  Pop the previous state of given `context` from its stack.

  Before evaluating an include mechanism, the current SPF's record state
  is pushed onto the stack.  This function restores that state from the
  stack.

  """
  @spec pop(t) :: t
  def pop(context) do
    case context.stack do
      [] ->
        log(context, :ctx, :error, "attempted to pop from empty stack")

      [state | tail] ->
        Map.put(context, :stack, tail)
        |> Map.merge(state)
        |> log(:ctx, :debug, "popped state, back to #{state.domain}")
    end
  end

  @doc """
  Push the current state of given `context` onto its stack and re-init the context.

  The details of the current SPF record are pushed onto a stack and the context
  is re-initialized for retrieving, parsing and evaluate a new `include`d
  record.

  """
  @spec push(t, binary) :: t
  def push(context, domain) do
    state = %{
      depth: context.depth,
      domain: context.domain,
      nth: context.nth,
      ast: context.ast,
      spf: context.spf,
      explain: context.explain
    }

    nth = context.num_spf

    tick(context, :num_spf)
    |> tick(:depth)
    |> trace(domain)
    |> Map.put(:stack, [state | context.stack])
    |> Map.put(:map, Map.merge(context.map, %{nth => domain, domain => ""}))
    |> Map.put(:domain, domain)
    |> Map.put(:nth, nth)
    |> Map.put(:ast, [])
    |> Map.put(:spf, "")
    |> Map.put(:explain, nil)
    |> log(:ctx, :debug, "pushed state for #{state.domain}")
  end

  @doc """
  Reinitializes current `context` for given `domain` of a redirect modifier.

  When a redirect modifier is encountered it basically replaces the current SPF
  record and the context is modified accordingly.

  """
  @spec redirect(t, binary) :: t
  def redirect(context, domain) do
    # do NOT empty the stack: a redirect modifier may be in an included record
    tick(context, :num_spf)
    |> trace(domain)
    |> Map.put(:depth, 0)
    |> Map.put(:nth, context.num_spf)
    |> Map.put(
      :map,
      Map.merge(context.map, %{context.num_spf => domain, domain => ""})
    )
    |> Map.put(:domain, domain)
    |> Map.put(:error, nil)
    |> Map.put(:ast, [])
    |> Map.put(:spf, "")
    |> Map.put(:explain, nil)
  end

  @doc """
  If `test` is true, logs the given `msg` with its `facility` and `severity`.

  A convencience function to quickly check some test and, if true, log it as
  well in one go.

  """
  @spec test(t, atom, atom, boolean, binary) :: t
  def test(context, facility, severity, test, msg)

  def test(context, facility, severity, true, msg),
    do: log(context, facility, severity, msg)

  def test(context, _, _, _, _),
    # nil is also false
    do: context

  @doc """
  Adds `delta` to `counter` and returns updated `context`.

  Valid counters include:
  - `:num_spf`, the number of SPF records seen
  - `:num_dnsm` the number of DNS mechanisms seen
  - `:num_dnsq` the number of DNS queries performed
  - `:num_dnsv` the number of void DNS queries seen
  - `:num_checks` the number of checks performed
  - `:num_warn` the number of warnings seen
  - `:num_error` the number of errors see (may not be fatal)
  - `:depth` the current recursion depth

  """
  @spec tick(t, atom, integer) :: t
  def tick(context, counter, delta \\ 1) do
    count = Map.get(context, counter, nil)

    if count do
      Map.put(context, counter, count + delta)
    else
      log(context, :ctx, :error, "unknown counter #{inspect(counter)} - ignored")
    end
  end
end
