defmodule SpfTest do
  use ExUnit.Case
  doctest Spf

  defp info(ctx) do
    dns_good = Spf.DNS.to_list(ctx) |> Enum.join("\n")
    dns_bad = Spf.DNS.to_list(ctx, valid: false) |> Enum.join("\n")
    msg = "\n\n"
    msg = msg <> "verdict #{ctx.verdict}\n"
    msg = msg <> "reason  #{ctx.reason}\n"
    msg = msg <> "error   #{ctx.error}\n\n"
    msg = msg <> "LOG\n" <> (Enum.map(ctx.msg, fn x -> inspect(x) end) |> Enum.join("\n"))
    msg = msg <> "\n\nDNS good\n" <> dns_good
    msg = msg <> "\n\nDNS bad\n" <> dns_bad
    msg <> "\n\n"
  end

  describe "domain name checks" do
    @describetag :domain_names
    test "001 - dns label > 63 chars is invalid" do
      # spec: 4.3/1, initial processing:
      # - an invalid dns label in domain -> None
      # - a DNS timeout -> TempError
      domain = "A123456789012345678901234567890123456789012345678901234567890123.example.com"
      sender = "lyme.eater@#{domain}"
      verdict = :none

      zonedata = """
      example.com TXT v=spf1 -all
      """

      ctx = Spf.check(sender, dns: zonedata)

      msg = "got #{ctx.verdict}, expected #{verdict}" <> info(ctx)
      assert ctx.verdict == :none, msg
      assert ctx.error != nil, msg
    end

    test "002 - dns label <= 63 chars is allowed" do
      # for initial processing, max label length is 63 chars
      # spec: 4.3/1
      domain = "A12345678901234567890123456789012345678901234567890123456789012.example.com"
      sender = "lyme.eater@#{domain}"
      ip = "1.2.3.5"

      zonedata = """
      example.com TXT TIMEOUT
      a12345678901234567890123456789012345678901234567890123456789012.example.com txt v=spf1 -all
      """

      ctx = Spf.check(sender, ip: ip, dns: zonedata)
      # first label is 63 chars, domain is valid -> -all yields a fail
      assert ctx.verdict == :fail, info(ctx)
    end

    test "003 - ptr domain spec must be valid" do
      sender = "someone@example.com"
      verdict = :permerror

      zonedata = """
      example.com TXT v=spf1 ptr:example.-com
      """

      ctx = Spf.check(sender, dns: zonedata)
      msg = "got #{ctx.verdict}, expected #{verdict}" <> info(ctx)
      assert ctx.verdict == verdict, msg
    end

    test "004 - ptr domain spec must be valid" do
      sender = "someone@example.com"
      verdict = :permerror

      zonedata = """
      example.com TXT v=spf1 ptr:example.123
      """

      ctx = Spf.check(sender, dns: zonedata)
      msg = "got #{ctx.verdict}, expected #{verdict}" <> info(ctx)
      assert ctx.verdict == verdict, msg
    end

    test "005 - exists domain spec must be valid" do
      sender = "someone@example.com"
      verdict = :permerror

      zonedata = """
      example.com TXT v=spf1 exists:example.123
      """

      ctx = Spf.check(sender, dns: zonedata)
      msg = "got #{ctx.verdict}, expected #{verdict}" <> info(ctx)
      assert ctx.verdict == verdict, msg
    end

    test "006 - include domain spec must be valid" do
      sender = "someone@example.com"
      verdict = :permerror

      zonedata = """
      # :permerror due to all numeric toplevel domain
      example.com TXT v=spf1 include:example.123
      example.123 A 1.2.3.4
      """

      ctx = Spf.check(sender, dns: zonedata)
      msg = "got #{ctx.verdict}, expected #{verdict}" <> info(ctx)
      assert ctx.verdict == verdict, msg
    end

    test "007 - redirect domain spec must be valid" do
      sender = "someone@example.com"
      verdict = :permerror

      zonedata = """
      # :permerror due to all numeric toplevel domain
      example.com TXT v=spf1 redirect:example.123
      example.123 TXT v=spf1 +all
      """

      ctx = Spf.check(sender, dns: zonedata)
      msg = "got #{ctx.verdict}, expected #{verdict}\n\n" <> info(ctx)
      assert ctx.verdict == verdict, msg
    end
  end

  describe "loop detection" do
    @describetag :loop_detection
    test "001 - including twice is not an error" do
      sender = "someone@example.com"
      verdict = :fail

      zonedata = """
      # including the same domain twice is not an error
      example.com TXT v=spf1 include:a.example.com include:a.example.com -all
      a.example.com TXT v=spf1 ~all
      """

      ctx = Spf.check(sender, dns: zonedata)

      msg =
        "got #{ctx.verdict}, expected #{verdict}" <> info(ctx) <> "\nctx.map\n#{inspect(ctx.map)}"

      assert ctx.verdict == verdict, msg
    end

    test "002 - including twice is not an error" do
      sender = "someone@example.com"
      verdict = :fail

      zonedata = """
      # :fail despite included domains
      example.com TXT v=spf1 include:a.example.com include:b.example.com -all
      a.example.com TXT v=spf1 include:c.example.com ~all
      b.example.com TXT v=spf1 include:c.example.com ~all
      c.example.com TXT v=spf1 ~all
      """

      ctx = Spf.check(sender, dns: zonedata)

      msg =
        "got #{ctx.verdict}, expected #{verdict}" <> info(ctx) <> "\nctx.map\n#{inspect(ctx.map)}"

      assert ctx.verdict == verdict, msg
    end

    test "003 - including self is permerror" do
      sender = "someone@example.com"
      verdict = :permerror

      zonedata = """
      # loop: example.com cannot include itself
      example.com TXT v=spf1 include:EXAMPLE.COM +all
      """

      ctx = Spf.check(sender, dns: zonedata)

      msg =
        "got #{ctx.verdict}, expected #{verdict}" <> info(ctx) <> "\nctx.map\n#{inspect(ctx.map)}"

      assert ctx.verdict == verdict, msg
    end

    test "004 - include loop is permerror" do
      sender = "someone@example.com"
      verdict = :permerror

      zonedata = """
      # loop: a.example.com cannot include example.com
      example.com TXT v=spf1 include:a.example.com +all
      a.example.com TXT v=spf1 include:example.com -all
      x.example.com TXT %{d} says %{i} is not ok
      """

      ctx = Spf.check(sender, dns: zonedata)

      msg =
        "got #{ctx.verdict}, expected #{verdict}" <> info(ctx) <> "\nctx.map\n#{inspect(ctx.map)}"

      assert ctx.verdict == verdict, msg
    end

    test "005 - repeated exists is not an error" do
      sender = "someone@example.com"
      verdict = :pass

      zonedata = """
      # :fail despite included domains
      example.com TXT v=spf1 exists:example.com exists:example.com -all
      example.com A 1.2.3.4
      """

      ctx = Spf.check(sender, dns: zonedata)
      msg = "got #{ctx.verdict}, expected #{verdict}" <> info(ctx)
      assert ctx.verdict == verdict, msg
    end

    test "006 - redirect loop is permerror" do
      sender = "someone@example.com"
      verdict = :permerror

      zonedata = """
      # loop: example.com cannot redirect to example.com
      example.com TXT v=spf1 redirect=example.com
      """

      ctx = Spf.check(sender, dns: zonedata)

      msg =
        "got #{ctx.verdict}, expected #{verdict}" <> info(ctx) <> "\nctx.map\n#{inspect(ctx.map)}"

      assert ctx.verdict == verdict, msg
    end

    test "007 - redirect loop is permerror" do
      sender = "someone@example.com"
      verdict = :permerror

      zonedata = """
      # loop: b.example.com cannot redirect to example.com
      example.com TXT v=spf1 redirect=b.example.com
      b.example.com TXT v=spf1 redirect=example.com
      """

      ctx = Spf.check(sender, dns: zonedata)

      msg =
        "got #{ctx.verdict}, expected #{verdict}" <> info(ctx) <> "\nctx.map\n#{inspect(ctx.map)}"

      assert ctx.verdict == verdict, msg
    end

    test "008 - redirect loop is permerror" do
      sender = "someone@example.com"
      verdict = :permerror

      zonedata = """
      # loop: example.com cannot redirect to example.com
      example.com TXT v=spf1 redirect=b.example.com
      b.example.com TXT v=spf1 redirect=c.example.com
      c.example.com TXT v=spf1 include:d.example.com
      d.example.com TXT v=spf1 redirect=b.example.com
      """

      ctx = Spf.check(sender, dns: zonedata)

      msg =
        "got #{ctx.verdict}, expected #{verdict}" <> info(ctx) <> "\nctx.map\n#{inspect(ctx.map)}"

      assert ctx.verdict == verdict, msg
    end

    test "009 - macro's won't hide a loop" do
      sender = "someone@example.com"
      verdict = :permerror

      zonedata = """
      # macro's won't hide a loop
      example.com TXT v=spf1 redirect=b.example.com
      b.example.com TXT v=spf1 redirect=c.example.com
      c.example.com TXT v=spf1 include:d.example.com
      d.example.com TXT v=spf1 redirect=b.%{d2}
      """

      ctx = Spf.check(sender, dns: zonedata)

      msg =
        "got #{ctx.verdict}, expected #{verdict}" <> info(ctx) <> "\nctx.map\n#{inspect(ctx.map)}"

      assert ctx.verdict == verdict, msg
    end

    test "010 - trailing dots don't fool the loop detection" do
      sender = "someone@example.com"
      verdict = :permerror

      zonedata = """
      example.com TXT v=spf1 redirect=b.example.com.
      b.example.com TXT v=spf1 redirect=c.example.com
      c.example.com. TXT v=spf1 redirect=example.com.
      """

      ctx = Spf.check(sender, dns: zonedata)

      msg =
        "got #{ctx.verdict}, expected #{verdict}" <> info(ctx) <> "\nctx.map\n#{inspect(ctx.map)}"

      assert ctx.verdict == verdict, msg
    end
  end

  describe "redirect" do
    test "001 - redirect evaluated last" do
      sender = "someone@example.com"
      ip = "1.2.3.4"
      verdict = :pass

      zonedata = """
      # redirect takes effect after all mechanisms have been evaluated
      example.com TXT v=spf1 redirect=b.example.com a
      example.com A 1.2.3.4
      b.example.com TXT v=spf1 -all
      """

      ctx = Spf.check(sender, ip: ip, dns: zonedata)

      msg =
        "got #{ctx.verdict}, expected #{verdict}" <> info(ctx) <> "\nctx.map\n#{inspect(ctx.map)}"

      assert ctx.verdict == verdict, msg
    end

    test "002 - redirect ignored if all is present" do
      sender = "someone@example.com"
      ip = "1.2.3.4"
      verdict = :pass

      zonedata = """
      example.com TXT v=spf1 redirect=b.example.com +all
      b.example.com TXT v=spf1 -all
      """

      ctx = Spf.check(sender, ip: ip, dns: zonedata)

      msg =
        "got #{ctx.verdict}, expected #{verdict}" <> info(ctx) <> "\nctx.map\n#{inspect(ctx.map)}"

      assert ctx.verdict == verdict, msg
    end
  end

  describe "mechanisms with servfail" do
    test "001 - ptr record has servfail" do
      sender = "someone@example.com"
      ip = "1.2.3.4"
      verdict = :temperror

      zonedata = """
      example.com TXT v=spf1 ptr +all
      4.3.2.1.in-addr.arpa ptr SERVFAIL
      """

      ctx = Spf.check(sender, ip: ip, dns: zonedata)

      msg =
        "got #{ctx.verdict}, expected #{verdict}" <> info(ctx) <> "\nctx.map\n#{inspect(ctx.map)}"

      assert ctx.verdict == verdict, msg
    end

    test "002 - mx record has servfail" do
      sender = "someone@example.com"
      ip = "1.2.3.4"
      verdict = :temperror

      zonedata = """
      example.com TXT v=spf1 mx +all
      example.com mx SERVFAIL
      """

      ctx = Spf.check(sender, ip: ip, dns: zonedata)

      msg =
        "got #{ctx.verdict}, expected #{verdict}" <> info(ctx) <> "\nctx.map\n#{inspect(ctx.map)}"

      assert ctx.verdict == verdict, msg
    end

    test "003 - txt has some unknown error" do
      sender = "someone@example.com"
      ip = "1.2.3.4"
      verdict = :temperror

      # need to manually set the dns cache, since reading RR's only supports
      # a subset of errors seen in the wild.

      ctx =
        Spf.Context.new(sender, ip: ip)
        |> Map.put(:dns, %{{"example.com", :txt} => {:error, :unknown_error}})
        |> Spf.Eval.evaluate()

      assert ctx.verdict == verdict
    end

    test "004 - txt has some unknown error" do
      sender = "someone@example.com"
      ip = "1.2.3.4"
      verdict = :temperror

      # need to manually set the dns cache, since reading RR's only supports
      # a subset of errors seen in the wild.  In this case, inet_res error
      # format is simulated similar to {:error, {:servfail, dns_msg}}

      ctx =
        Spf.Context.new(sender, ip: ip)
        |> Map.put(:dns, %{{"example.com", :txt} => {:error, {:unknown_error, "unknown error"}}})
        |> Spf.Eval.evaluate()

      assert ctx.verdict == verdict
    end
  end

  describe "verdict is correct" do
    test "001 - -all does not add sender's ip to ctx.ipt" do
      sender = "someone@example.com"
      ip = "1.2.3.4"
      verdict = :pass

      zonedata = """
      # -all does not add sender's ip to the ip table if it did, the
      # ip4-mechanism would not be a longest prefix match anymore

      example.com TXT v=spf1 include:a.example.com include:b.example.com ip4:1.2.3.0/24 -all
      a.example.com TXT v=spf1 -all
      b.example.com TXT v=spf1 -all
      """

      ctx = Spf.check(sender, ip: ip, dns: zonedata)

      msg =
        "got #{ctx.verdict}, expected #{verdict}" <> info(ctx) <> "\nctx.map\n#{inspect(ctx.map)}"

      assert ctx.verdict == verdict, msg
    end
  end

  describe "warnings about inconsistent entries" do
    test "001 - detect multiple, inconsistent entries" do
      zonedata = """
      example.com TXT v=spf1 -a +a -mx +mx -ip4:10.10.10.10 +ip4:10.10.10.10
      example.com A 10.10.10.10
      example.com MX 10 mail.example.com
      mail.example.com A 11.11.11.11
      """

      ctx = Spf.check("someone@example.com", dns: zonedata)

      warnings =
        Enum.filter(ctx.msg, fn {_nth, _facility, type, _msg} -> type == :warn end)
        |> Enum.map(fn {_, _, _, msg} -> msg end)
        |> Enum.filter(&String.contains?(&1, "inconsistent"))

      assert length(warnings) > 0
    end

    test "002 - detect multiple, inconsistent entries across SPF's" do
      zonedata = """
      example.com   TXT v=spf1 -ip4:10.10.10.10 include:a.example.com -all
      a.example.com TXT v=spf1 ip4:10.10.10.10
      """

      ctx = Spf.check("someone@example.com", dns: zonedata)

      warnings =
        Enum.filter(ctx.msg, fn {_nth, _facility, type, _msg} -> type == :warn end)
        |> Enum.map(fn {_, _, _, msg} -> msg end)
        |> Enum.filter(&String.contains?(&1, "inconsistent"))

      assert length(warnings) > 0
    end
  end

  describe "warnings about prefix lengths" do
    test "001 - warn about a/mx/ip4/ip6-mech's with zero prefix" do
      zonedata = """
      example.com   TXT v=spf1 a/0 mx/0 ip4:1.1.1.1/0 ip6:acdc::/0 -all
      """

      ctx = Spf.check("someone@example.com", dns: zonedata)

      warnings =
        Enum.filter(ctx.msg, fn {_nth, _facility, type, _msg} -> type == :warn end)
        |> Enum.map(fn {_, _, _, msg} -> msg end)
        |> Enum.filter(&String.contains?(&1, "ZERO"))

      assert length(warnings) == 4
    end

    test "002 - warn about a/mx-mech's with macros and zero prefix" do
      zonedata = """
      example.com   TXT v=spf1 a:%{d}/0 mx:%{d}/0 -all
      """

      ctx = Spf.check("someone@example.com", dns: zonedata)

      warnings =
        Enum.filter(ctx.msg, fn {_nth, _facility, type, _msg} -> type == :warn end)
        |> Enum.map(fn {_, _, _, msg} -> msg end)
        |> Enum.filter(&String.contains?(&1, "ZERO"))

      assert length(warnings) == 2
    end

    test "003 - warn about a/mx/ip4/ip6-mech's with max len4 prefix" do
      zonedata = """
      example.com   TXT v=spf1 a/32 mx/32 ip4:1.1.1.1/32 ip6:acdc::/128 -all
      """

      ctx = Spf.check("someone@example.com", dns: zonedata)

      warnings =
        Enum.filter(ctx.msg, fn {_nth, _facility, type, _msg} -> type == :warn end)
        |> Enum.map(fn {_, _, _, msg} -> msg end)
        |> Enum.filter(&String.contains?(&1, "default mask"))

      assert length(warnings) > 0
    end
  end

  describe "Spf.check without options" do
    # for illegal names, verdict will be none.
    # https://www.rfc-editor.org/rfc/rfc7208.html#section-4.3
    test "01 - no options" do
      # localhost not multilabel
      ctx = Spf.check("localhost")
      assert :none == ctx.verdict
    end

    test "02 - domain name too long" do
      domain = String.duplicate("abcdefghi.", 26) <> "com"
      assert String.length(domain) > 253
      ctx = Spf.check(domain)
      assert :none == ctx.verdict
    end
  end
end
