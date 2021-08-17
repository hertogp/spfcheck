defmodule Spf.Utils do
  @moduledoc """
  Helper functions for all Spf modules
  """

  @doc """
  Returns a map with macroletters expansions for given `domain`, `ip` and `sender`.

  Uppercase macro letters expand as their lowercase variants, but are URL escaped.

  """
  def macros(domain, ip, sender) do
    pfx = Pfx.new(ip)
    tstamp = DateTime.utc_now() |> DateTime.to_unix()

    m = %{
      # d = <domain>
      ?d => domain,
      # c = SMTP client IP (easily readable format)
      ?c => "#{pfx}",
      # i = <ip>, for ip6 this expands to dotted format
      ?i => if(pfx.maxlen == 32, do: "#{pfx}", else: Pfx.format(pfx, width: 4, base: 16)),
      # s = <sender>
      ?s => sender,
      # o = domain of <sender> (after last @ in sender)
      ?o => String.replace(sender, ~r(^.*@), ""),
      # l = local-part of <sender> (before last @ in sender)
      ?l => String.replace(sender, ~r(@[^@]*$), ""),
      # p = the validated domain name of <ip> (do not use)
      ?p => Pfx.dns_ptr(ip),
      # v = the string "in-addr" if <ip> is ipv4, or "ip6" if <ip> is ipv6
      ?v => (pfx.maxlen == 32 && "in-addr") || "ip6",
      # h = HELO/EHLO domain (fake it with domain part of sender)
      ?h => String.replace(sender, ~r(^.*@), ""),
      # r = domain name of host performing the check
      ?r => "localhost"
    }

    # add uppercase variants: they are URL escaped (except for ?t and ?T)
    Enum.reduce(m, m, fn {k, v}, m -> Map.put(m, k - 32, URI.encode(v)) end)
    |> Map.put(?t, tstamp)
    |> Map.put(?T, tstamp)
  end

  @doc """
  Returns a context map for SPF parsing and evaluation.

  During recursive calls, only `domain` may change.  

  """
  def context(domain, opts \\ []) do
    ip = Keyword.get(opts, :ip, "127.0.0.1")
    sender = Keyword.get(opts, :sender, "postmaster@host.local")
    atype = if Pfx.new(ip).maxlen == 32, do: :a, else: :aaaa
    mletters = macros(domain, ip, sender)

    %{
      # <domain> to provide authorisation
      domain: domain,
      ip: ip,
      atype: atype,
      sender: sender,
      opts: opts,
      verdict: "unknown",
      # dns cache
      dns: Keyword.get(opts, :dns, %{}),
      macro: mletters,
      # spf counter
      num_spf: Keyword.get(opts, :num_spf, 0),
      cur_spf: Keyword.get(opts, :cur_spf, 0),
      # maps num_spf -> domain, domain -> num_spf
      d2d: %{},
      # maps num_spf -> macros
      mstack: %{0 => mletters},
      # verbosity level, default is errors + warnings + notes, not info
      verbosity: Keyword.get(opts, :verbosity, 3),
      # parser/eval messages
      msg: [],
      # parser state flags
      flags: %{},
      # track/guard overall dns queries, void lookups and dns mechanisms
      num_dnsq: 0,
      num_dnsv: 0,
      num_dnsm: 0,
      max_dnsq: 10,
      max_dnsv: 2,
      max_dnsm: 10,
      num_checks: 0,
      ast: [],
      # calculated afterwards relative to macro[?t]
      duration: 0,
      # ip -> [{qualifier, depth, domain, token}]
      ipt: Iptrie.new()
    }
  end

  @doc """
  Add key,value pair to `ctx.ipt`.

  """
  def addip(ctx, ips, dual, value) when is_list(ips) do
    kvs = Enum.map(ips, fn ip -> {prefix(ip, dual), value} end)
    Map.put(ctx, :ipt, Iptrie.put(ctx[:ipt], kvs))
  end

  defp prefix(ip, [len4, len6]) do
    pfx = Pfx.new(ip)

    case pfx.maxlen do
      32 -> Pfx.keep(pfx, len4)
      _ -> Pfx.keep(pfx, len6)
    end
  end

  def log(ctx, type, str) do
    IO.puts(:stderr, "[#{type}] #{str}")
    Map.update(ctx, :msg, [{type, str}], fn msgs -> [{type, str} | msgs] end)
  end

  def log(ctx, type, {_token, _tokval, range} = token, msg) do
    start = range.first
    tokstr = String.slice(ctx[:spf], range)
    IO.puts(:stderr, "[#{type}] col #{start}: '#{tokstr}' - #{msg}")
    Map.update(ctx, :msg, [{type, token, msg}], fn msgs -> [{type, token, msg} | msgs] end)
  end

  # check if string contains v=spf, even if malformed
  @doc """
  Returns true when `str` looks like an SPF record, false otherwise

  """
  @spec spf?(binary) :: boolean
  def spf?(str) when is_binary(str) do
    str
    |> String.downcase()
    |> String.replace([" ", "\t", "\n", "\r"], "")
    |> String.contains?("v=spf1")
  end

  def spf?(_),
    do: false

  # CONTEXT

  @doc """
  Increment `counter` by one, returns updated `context`.

  If `counter` is not present in `context`, it will be created.

  """
  @spec tick(map, atom) :: map
  def tick(ctx, counter) when is_atom(counter),
    do: Map.update(ctx, counter, 0, fn n -> n + 1 end)
end
