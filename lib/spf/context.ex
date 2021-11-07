defmodule Spf.Context do
  @moduledoc """
  Functions to create, access and update an SPF evaluation context.
  """

  @type t :: %{
          # args
          :sender => binary(),
          :local => binary(),
          :ip => binary(),
          :domain => binary(),
          :helo => binary(),
          # parsing
          :spf_tokens => list(),
          :ast => list(),
          # results
          :verdict => atom(),
          :explain => tuple() | nil,
          :explain_string => binary(),
          :explanation => binary(),
          :error => binary() | nil,
          :reason => binary(),
          # tracking
          :nth => non_neg_integer(),
          :num_spf => non_neg_integer(),
          :traces => map(),
          :stack => list(),
          :ipt => Iptrie.t(),
          :t0 => non_neg_integer(),
          :duration => non_neg_integer(),
          # logging
          :log => function(),
          :map => map(),
          :verbosity => non_neg_integer(),
          :depth => non_neg_integer(),
          :msg => list(),
          # dns
          :atype => :a | :aaaa,
          :dns => map(),
          :dns_timeout => non_neg_integer(),
          :max_dnsm => non_neg_integer(),
          :num_dnsm => non_neg_integer(),
          :max_dnsq => non_neg_integer(),
          :num_dnsq => non_neg_integer(),
          :max_dnsv => non_neg_integer(),
          :num_dnsv => non_neg_integer()
        }

  # Helpers

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
  def addip(ctx, ips, dual, value) when is_list(ips) do
    kvs =
      Enum.map(ips, fn ip -> {prefix(ip, dual), value} end)
      |> Enum.filter(fn {k, _v} -> k != :error end)

    Enum.reduce(kvs, ctx, &ipt_update/2)
  end

  def addip(ctx, ip, dual, value) when is_binary(ip) do
    ipt_update({prefix(ip, dual), value}, ctx)
  end

  def error(ctx, error, reason, verdict \\ nil) do
    Map.put(ctx, :error, error)
    |> Map.put(:reason, reason)
    |> Map.put(:verdict, verdict || ctx.verdict)
    |> log(:eval, :error, reason)
  end

  @doc """
  Returns the SPF string for `nth` domain if available, nil otherwise.

  """
  @spec get_spf(map, integer | binary) :: binary
  def get_spf(ctx, nth) when is_integer(nth) do
    with domain when is_binary(domain) <- ctx.map[nth] do
      get_spf(ctx, domain)
    else
      _ -> "ERROR SPF[#{nth}] NOT FOUND"
    end
  end

  def get_spf(ctx, domain) when is_binary(domain) do
    case Spf.DNS.from_cache(ctx, domain, :txt) do
      {:ok, []} -> "ERROR SPF NOT FOUND"
      {:ok, rrs} -> Enum.find(rrs, "ERROR SPF NOT FOUND", &Spf.Eval.spf?/1)
      {:error, _} -> "ERROR SPF NOT FOUND"
    end
  end

  def spf_term(ctx, range),
    do: "spf[#{ctx.nth}] #{String.slice(ctx.spf, range)}"

  @spec log(map, atom, atom, binary) :: map
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

  def loop?(ctx, new_domain) do
    new_domain = String.downcase(new_domain)
    cur_domain = String.downcase(ctx.domain)
    cur_domain in Map.get(ctx.traces, new_domain, [])
  end

  defp trace(ctx, new_domain) do
    new_domain = String.downcase(new_domain)
    cur_domain = String.downcase(ctx.domain)

    Map.update(ctx.traces, cur_domain, [], fn v -> v end)
    |> Enum.reduce(%{}, fn {k, v}, acc -> Map.put(acc, k, [new_domain | v]) end)
    |> then(fn traces -> Map.put(ctx, :traces, traces) end)
  end

  def split(mbox) do
    # local@local@domain -> {local@local, domain}, local part is upto last `@`
    # TODO: right now, split("domain@domain") -> {postmaster, domain} instead
    # of {domain, domain} ... although its an edge case.
    domain = String.replace(mbox, ~r/^.*@/, "")

    local =
      case String.replace(mbox, ~r/@[^@]*$/, "") do
        "" -> "postmaster"
        ^domain -> "postmaster"
        local -> local
      end

    {local, domain}
  end

  @doc """
  Returns a new context map for an SPF evaluation.

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
  def new(sender, opts \\ []) do
    # TODO: check validity of user supplied IP address
    helo = Keyword.get(opts, :helo, sender)
    {local, domain} = split(sender)

    {local, domain} =
      if String.length(domain) < 1,
        do: split(helo),
        else: {local, domain}

    # IPV4-mapped IPv6 addresses are converted to the mapped IPv4 address
    ip = Keyword.get(opts, :ip, "127.0.0.1")
    pfx = Pfx.new(ip)

    pfx =
      if Pfx.member?(pfx, "::FFFF:0:0/96"),
        do: Pfx.cut(pfx, -1, -32),
        else: pfx

    atype = if pfx.maxlen == 32 or Pfx.member?(pfx, "::FFFF:0/96"), do: :a, else: :aaaa

    %{
      # <sender> that is using <ip> to send mail
      sender: sender,
      # local part of sender
      local: local,
      # optional helo argument
      helo: helo,
      # current <domain> whose authorisation is evaluated
      domain: domain,
      # <ip> for which authorization is sought
      ip: "#{pfx}",
      # the nth spf record under consideration
      nth: 0,
      # current recursion depth (for pretty logging)
      depth: 0,
      # linear increasing count of spf records
      num_spf: 1,
      # tracks what was seen before: nth=>domain, domain=>nth; for reporting
      map: %{0 => domain, domain => 0},
      # traces records series of domains seen, for loop detection
      traces: %{},
      # push state (part of ctx) when recursing on include'd domains
      stack: [],
      # type of A RR lookup (A or AAAA), depends on <ip>
      atype: atype,
      # user log function, or local one.
      log: Keyword.get(opts, :log, nil),
      # default verdict is ?all, ie neutral
      verdict: :neutral,
      # what actually caused a match
      reason: "",
      # default :inet_res timeout in msec
      dns_timeout: 2000,
      # dns cache {key, type} => [value]
      dns: %{},
      # no dns error seen (yet)
      error: nil,
      verbosity: Keyword.get(opts, :verbosity, 4),
      # log of messages, whether outputted or not
      msg: [],
      # explain term (if any)
      explain: nil,
      explain_string: "",
      explanation: "",
      # stats
      num_dnsq: 0,
      num_dnsm: 0,
      max_dnsm: 10,
      num_dnsv: 0,
      max_dnsv: 2,
      num_checks: 0,
      num_warn: 0,
      num_error: 0,
      # list of terms to be evaluated to arrive at a verdict
      ast: [],
      # list of tokens found by the lexer
      spf_tokens: [],
      # how long the evaluation took; warn if it took > 20 sec!
      duration: 0,
      # ipt.lookup(ip) -> [{q, nth}, ..], if len(list) > 1 -> duplicate ip's seen
      ipt: Iptrie.new(),
      # report back
      # report: Keyword.get(opts, :report, :short),
      t0: DateTime.utc_now() |> DateTime.to_unix()
    }
    |> Spf.DNS.load(Keyword.get(opts, :dns, nil))
    |> log(:ctx, :debug, "created context for #{domain}")
    |> log(:spf, :note, "spfcheck(#{domain}, #{pfx}, #{sender})")

    # |> Spf.DNS.load_file(Keyword.get(opts, :dns, nil))
  end

  @doc """
  Pop the previous state of given `ctx` from its stack.

  """
  @spec pop(map) :: map
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
  @spec push(map, binary) :: map
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
  end

  @doc """
  Reinitializes current `ctx` for given `domain` of a redirect modifier.

  """
  @spec redirect(map, binary) :: map
  def redirect(ctx, domain) do
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
  """
  def test(ctx, facility, severity, test, msg)

  def test(ctx, facility, severity, true, msg),
    do: log(ctx, facility, severity, msg)

  def test(ctx, _, _, _, _),
    # nil is also false
    do: ctx

  @doc """
  Add `delta` to `counter`, returns updated `context`.

  If `counter` is not present in `context`, it will be created.

  """
  @spec tick(map, atom, integer) :: map
  def tick(ctx, counter, delta \\ 1) when is_atom(counter),
    do: Map.update(ctx, counter, delta, fn n -> n + delta end)
end
