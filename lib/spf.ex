defmodule Spf do
  @moduledoc """
  Functions to get and debug SPF records.
  """
  import NimbleParsec

  alias Spfcheck.DNS
  import Spf.Tokens

  # TODO REMOVE
  def example() do
    domain = "rws.nl"
    ip = "127.0.0.1"
    sender = "me@localhost"

    context = %{
      spf: [" v=spf1 a a:%{d} a:%{d1r.}"],
      domain: domain,
      ip: ip,
      sender: sender,
      opts: [],
      verdict: "unknown",
      dns: %{},
      macro: mletters(domain, ip, sender),
      verbosity: 3,
      msg: [],
      flags: %{}
    }

    context
    |> parse()
    |> check()
  end

  defp grep(ctx) do
    {ctx, result} = DNS.resolve(ctx, ctx[:domain], :txt)

    case DNS.grep(result, &spf?/1) do
      {:ok, spf} -> Map.put(ctx, :spf, spf)
      {:error, reason} -> Map.put(ctx, :error, reason) |> Map.put(:spf, [])
    end
  end

  # check if string contains v=spf, even if malformed
  def spf?(str) when is_binary(str) do
    str
    |> String.downcase()
    |> String.replace([" ", "\t", "\n", "\r"], "")
    |> String.contains?("v=spf1")
  end

  def spf?(_),
    do: false

  defparsec(:tokenize, Spf.Tokens.terms())
  defdelegate parse(context), to: Spf.Parser

  def mletters(domain, ip, sender) do
    pfx = Pfx.new(ip)

    %{
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
      ?r => "localhost",
      # t = current timestamp (epoch seconds)
      ?t => DateTime.utc_now() |> DateTime.to_unix()
    }
  end

  def eval(domain, opts \\ []) do
    ip = Keyword.get(opts, :ip, "127.0.0.1")
    sender = Keyword.get(opts, :sender, "postmaster@host.local")
    macros = mletters(domain, ip, sender)

    context = %{
      # <domain> to provide authorisation
      domain: domain,
      ip: ip,
      sender: sender,
      opts: opts,
      verdict: "unknown",
      # dns cache
      dns: Keyword.get(opts, :dns, %{}),
      macro: macros,
      # recursion level
      depth: 0,
      # used to restore macro after recursive call returns
      mstack: %{0 => macros},
      # verbosity level, default is errors + warnings + notes, not info
      verbosity: Keyword.get(opts, :verbosity, 3),
      # parser/eval messages
      msg: [],
      # parser state flags
      flags: %{},
      # track/guard overall dns queries, void lookups and dns mechanisms
      num_dnsq: 0,
      max_dnsq: 10,
      num_dnsv: 0,
      max_dnsv: 2,
      num_dnsm: 0,
      max_dnsm: 10,
      # maps depth->domain, domain->depth
      map: %{},
      ast: []
    }

    context
    |> grep()
    |> parse()
    |> check()
  end

  def check(x) do
    IO.inspect(x, label: :x)
    Map.get(x, :verdict, "oops")
  end
end
