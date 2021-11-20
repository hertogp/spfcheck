defmodule Spf.Context do
  @moduledoc """
  Functions to create, access and update an SPF evaluation context.

  """

  @typedoc """
  An SPF evaluation result.
  """
  @type verdict :: :fail | :neutral | :none | :pass | :permerror | :softfail | :temperror

  @typedoc """
  An SPF evaluation context.
  """
  @type t :: %{
          :ast => list(),
          :atype => :a | :aaaa,
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
          :log => function(),
          :map => map(),
          :max_dnsm => non_neg_integer(),
          :max_dnsv => non_neg_integer(),
          :msg => list(),
          :nth => non_neg_integer(),
          :num_checks => non_neg_integer(),
          :num_dnsm => non_neg_integer(),
          :num_dnsq => non_neg_integer(),
          :num_dnsv => non_neg_integer(),
          :num_error => non_neg_integer(),
          :num_spf => non_neg_integer(),
          :num_warn => non_neg_integer(),
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

  @type token :: Spf.Tokens.token()
  @type prefix :: Pfx.prefix()
  @type iptval :: {token, non_neg_integer}

  # Helpers

  @spec ipt_update({prefix, iptval}, t) :: t
  defp ipt_update({k, v}, ctx) do
    data = Iptrie.lookup(ctx.ipt, k)
    ipt = Iptrie.update(ctx.ipt, k, [v], fn list -> [v | list] end)

    seen_before =
      case data do
        nil -> false
        {k2, _v} -> not Pfx.member?(ctx.ip, k2)
      end

    Map.put(ctx, :ipt, ipt)
    |> log(:ipt, :debug, "UPDATE: #{k} -> #{inspect(v)}")
    |> test(:ipt, :warn, seen_before, "#{k} seen before: #{inspect(data)}")
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

  # API CONTEXT

  @doc """
  Update `ctx.ipt` with one or more ip,value-pairs.

  When given a list op ip's, they all will be be updated with given `value`
  which should consist of a tuple `{q, nth, term}` which records the SPF record
  and term (including the qualifier) that attributed the ip or ip's.

  """
  @spec addip(t, list(), list(), any) :: t
  def addip(ctx, ips, dual, value) when is_list(ips) do
    kvs =
      Enum.map(ips, fn ip -> {prefix(ip, dual), value} end)
      |> Enum.filter(fn {k, _v} -> k != :error end)

    Enum.reduce(kvs, ctx, &ipt_update/2)
  end

  @spec addip(t, binary, list(), iptval) :: t
  def addip(ctx, ip, dual, value) when is_binary(ip) do
    case prefix(ip, dual) do
      :error -> log(ctx, :ctx, :error, "ignored malformed IP #{ip}")
      pfx -> ipt_update({pfx, value}, ctx)
    end
  end

  @doc """
  Set an `error`, its `reason` and log it and return the updated `ctx`.

  """
  @spec error(t, atom, binary, nil | atom) :: t
  def error(ctx, error, reason, verdict \\ nil) do
    Map.put(ctx, :error, error)
    |> Map.put(:reason, reason)
    |> Map.put(:verdict, verdict || ctx.verdict)
    |> log(:eval, :error, reason)
  end

  @doc """
  Returns a previous SPF string given either its `domain` of `nth`-tracking number.

  Used for reporting rather than evalutation an SPF record.

  """
  @spec get_spf(t, integer | binary) :: binary
  def get_spf(ctx, nth) when is_integer(nth) do
    with domain when is_binary(domain) <- ctx.map[nth] do
      get_spf(ctx, domain)
    else
      _ -> "ERROR SPF[#{nth}] NOT FOUND"
    end
  end

  def get_spf(ctx, domain) when is_binary(domain) do
    case Spf.DNS.from_cache(ctx, domain, :txt) do
      # {:ok, []} -> "ERROR SPF NOT FOUND"
      {:error, _} -> "ERROR SPF NOT FOUND"
      {:ok, rrs} -> Enum.find(rrs, "ERROR SPF NOT FOUND", &Spf.Eval.spf?/1)
    end
  end

  @doc """
  Given a current `ctx` and a range, return the SPF term in that range.

  Retrieves a slice of the `ctx.spf` current record being evaluated.
  Used for logging events.

  """
  @spec spf_term(t, Range.t()) :: binary
  def spf_term(ctx, range),
    do: "spf[#{ctx.nth}] #{String.slice(ctx.spf, range)}"

  @doc """
  Updates `ctx`'s message queue and, if available, calls the user supplied log
  function.

  The `log/4` is called with:
  - `ctx` the current context/state of the evalution
  - `facility` an atom denoting which part of the program emitted the event
  - `severity` an atom describing the severity
  - `msg` a binary with event details

  """

  @spec log(t, atom, atom, binary) :: t
  def log(ctx, facility, severity, msg) do
    if ctx[:log],
      do: ctx.log.(ctx, facility, severity, msg)

    nth = Map.get(ctx, :nth, 0)

    ctx =
      Map.update(ctx, :msg, [{nth, facility, severity, msg}], fn msgs ->
        [{nth, facility, severity, msg} | msgs]
      end)

    case severity do
      :warn -> tick(ctx, :num_warn)
      :error -> tick(ctx, :num_error)
      _ -> ctx
    end
  end

  @doc """
  Returns true if `new_domain` constitues a loop for given `ctx`, false
  otherwise.

  Used to break a loop when two domains (eventually) include or redirect to
  each other.

  """
  @spec loop?(t, binary) :: boolean
  def loop?(ctx, new_domain) do
    new_domain = String.downcase(new_domain)
    cur_domain = String.downcase(ctx.domain)
    cur_domain in Map.get(ctx.traces, new_domain, [])
  end

  @spec trace(t, binary) :: t
  defp trace(ctx, new_domain) do
    new_domain = String.downcase(new_domain)
    cur_domain = String.downcase(ctx.domain)

    Map.update(ctx.traces, cur_domain, [], fn v -> v end)
    |> Enum.reduce(%{}, fn {k, v}, acc -> Map.put(acc, k, [new_domain | v]) end)
    |> then(fn traces -> Map.put(ctx, :traces, traces) end)
  end

  @doc """
  Split an email address into a local and a domain part.

  The local part is left to the left-most `@`, if there is no local
  part it defaults to "postmaster".  Note that splitting an empty
  string yields `{"postmaster", ""}`.

  """
  @spec split(binary) :: {binary, binary}
  def split(mbox) do
    words = String.split(mbox, "@", parts: 2, trim: true)

    case words do
      [] -> {"postmaster", ""}
      [local, domain] -> {local, domain}
      [domain] -> {"postmaster", domain}
    end
  end

  @doc """
  Returns a new [`context`](`t:Spf.Context.t/0`) for an SPF evaluation.

  The initial `domain` is derived from given `sender` and `ip` defaults to
  `127.0.0.1` if not given via the `ip:` option.  The context is used for the
  entire SPF evaluation, including during any recursive calls.

  When evaluating an `include` mechanism, the current state (a few selected
  context properties) is pushed onto an internal stack and a new `domain` is
  set directly.  After evaluating the `include` mechanism, the state if popped
  and the results are processed according to the `include`-mechanism's
  qualifier.

  When evaluating a `redirect` modifier, the current state is altered for the
  new domain specified by the modifier.

  """
  @spec new(binary, Keyword.t()) :: t
  def new(sender, opts \\ []) do
    helo = Keyword.get(opts, :helo, sender)
    {local, domain} = split(sender)

    {local, domain} =
      if String.length(domain) < 1,
        do: split(helo),
        else: {local, domain}

    # IPV4-mapped IPv6 addresses are converted to the mapped IPv4 address
    # note: check validity of user supplied IP address, default to 127.0.0.1
    ip = Keyword.get(opts, :ip, "127.0.0.1")

    pfx =
      try do
        Pfx.new(ip)
      rescue
        ArgumentError -> Pfx.new("127.0.0.1")
      end

    pfx =
      if Pfx.member?(pfx, "::FFFF:0:0/96"),
        do: Pfx.cut(pfx, -1, -32),
        else: pfx

    atype = if pfx.maxlen == 32 or Pfx.member?(pfx, "::FFFF:0/96"), do: :a, else: :aaaa

    %{
      ast: [],
      atype: atype,
      depth: 0,
      dns: %{},
      dns_timeout: 2000,
      domain: domain,
      duration: 0,
      error: nil,
      explain: nil,
      explain_string: "",
      explanation: "",
      helo: helo,
      ip: "#{pfx}",
      ipt: Iptrie.new(),
      local: local,
      log: Keyword.get(opts, :log, nil),
      map: %{0 => domain, domain => 0},
      max_dnsm: 10,
      max_dnsv: 2,
      msg: [],
      nth: 0,
      num_checks: 0,
      num_dnsm: 0,
      num_dnsq: 0,
      num_dnsv: 0,
      num_error: 0,
      num_spf: 1,
      num_warn: 0,
      reason: "",
      sender: sender,
      spf: "",
      spf_rest: "",
      spf_tokens: [],
      stack: [],
      t0: DateTime.utc_now() |> DateTime.to_unix(),
      traces: %{},
      verbosity: Keyword.get(opts, :verbosity, 4),
      verdict: :neutral
    }
    |> Spf.DNS.load(Keyword.get(opts, :dns, nil))
    |> log(:ctx, :debug, "created context for #{domain}")
    |> log(:spf, :note, "spfcheck(#{domain}, #{pfx}, #{sender})")
  end

  @doc """
  Pop the previous state of given `ctx` from its stack.

  """
  @spec pop(t) :: t
  def pop(ctx) do
    case ctx.stack do
      [] ->
        log(ctx, :ctx, :error, "attempted to pop from empty stack")

      [state | tail] ->
        Map.put(ctx, :stack, tail)
        |> Map.merge(state)
        |> log(:ctx, :debug, "popped state, back to #{state.domain}")
    end
  end

  @doc """
  Push the current state of given `ctx` onto its stack and re-init the context.

  The details of the current SPF record are pushed onto a stack and the context
  is re-initialized for retrieving, parsing and evaluate a new `include`d
  record.

  """
  @spec push(t, binary) :: t
  def push(ctx, domain) do
    state = %{
      depth: ctx.depth,
      domain: ctx.domain,
      nth: ctx.nth,
      ast: ctx.ast,
      spf: ctx.spf,
      explain: ctx.explain
    }

    nth = ctx.num_spf

    tick(ctx, :num_spf)
    |> tick(:depth)
    |> trace(domain)
    |> Map.put(:stack, [state | ctx.stack])
    |> Map.put(:map, Map.merge(ctx.map, %{nth => domain, domain => nth}))
    |> Map.put(:domain, domain)
    |> Map.put(:nth, nth)
    |> Map.put(:ast, [])
    |> Map.put(:spf, "")
    |> Map.put(:explain, nil)
    |> log(:ctx, :debug, "pushed state for #{state.domain}")
  end

  @doc """
  Reinitializes current `ctx` for given `domain` of a redirect modifier.

  """
  @spec redirect(t, binary) :: t
  def redirect(ctx, domain) do
    # do NOT empty the stack: a redirect modifier may be in an included record
    tick(ctx, :num_spf)
    |> trace(domain)
    |> Map.put(:depth, 0)
    |> Map.put(:nth, ctx.num_spf)
    |> Map.put(:map, Map.merge(ctx.map, %{ctx.num_spf => domain, domain => ctx.num_spf}))
    |> Map.put(:domain, domain)
    |> Map.put(:error, nil)
    |> Map.put(:ast, [])
    |> Map.put(:spf, "")
    |> Map.put(:explain, nil)
  end

  @doc """
  Adds `label`ed log `msg` to given `ctx`, if `test` is true

  A convencience function to quickly perform some test (in the call)
  and if true log it as well.

  """
  @spec test(t, atom, atom, boolean, binary) :: t
  def test(ctx, facility, severity, test, msg)

  def test(ctx, facility, severity, true, msg),
    do: log(ctx, facility, severity, msg)

  def test(ctx, _, _, _, _),
    # nil is also false
    do: ctx

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
  def tick(ctx, counter, delta \\ 1) do
    count = Map.get(ctx, counter, nil)

    if count do
      Map.put(ctx, counter, count + delta)
    else
      log(ctx, :ctx, :error, "unknown counter #{inspect(counter)} - ignored")
    end
  end
end
