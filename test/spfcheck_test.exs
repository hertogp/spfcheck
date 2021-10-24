defmodule SpfcheckTest do
  use ExUnit.Case
  doctest Spfcheck

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

  # TODO:
  # - remove this if it's not going to be used for testing via zonedata files
  # defp kvs(ctx, domain) do
  #   ctx = Map.put(ctx, :num_dnsq, 0)
  #   {_, rrs} = Spf.DNS.resolve(ctx, domain, type: :txt, stats: false)
  #   {:ok, [l]} = Spf.DNS.grep(rrs, fn x -> String.match?(x, ~r/^spfcheck/i) end)

  #   String.replace(l, ~r/^\s*spfcheck\s*/i, "")
  #   |> String.split(~r/,\s*/)
  #   |> Enum.map(fn x -> String.split(x, "=", parts: 2) end)
  #   |> Enum.map(fn l -> List.to_tuple(l) end)
  #   |> Enum.map(fn {k, v} -> {String.to_atom(k), v} end)
  #   |> Enum.into(%{})
  # rescue
  #   err -> IO.inspect(err, label: :err)
  # end

  describe "domain name checks" do
    @describetag :domain_names
    test "001 - dns labels limited to 63 chars" do
      # spec: 4.3/1, initial processing:
      # - an invalid dns label in domain -> None
      # - a DNS timeout -> TempError
      domain = "A123456789012345678901234567890123456789012345678901234567890123.example.com"
      sender = "lyme.eater@#{domain}"
      verdict = :none

      zonedata = """
      example.com TXT v=spf1 -all
      """

      ctx =
        Spf.Context.new(sender)
        |> Spf.DNS.load_lines(zonedata)
        |> Spf.Eval.evaluate()

      msg = "got #{ctx.verdict}, expected #{verdict}" <> info(ctx)
      assert ctx.verdict == :none, msg
      assert ctx.error != nil, msg
    end

    test "002 - dns labels limited to 63 chars" do
      # for initial processing, max label length is 63 chars
      # spec: 4.3/1
      domain = "A12345678901234567890123456789012345678901234567890123456789012.example.com"
      sender = "lyme.eater@#{domain}"
      ip = "1.2.3.5"

      zonedata = """
      example.com TXT TIMEOUT
      a12345678901234567890123456789012345678901234567890123456789012.example.com txt v=spf1 -all
      """

      ctx =
        Spf.Context.new(domain, sender: sender, ip: ip)
        |> Spf.DNS.load_lines(zonedata)
        |> Spf.Eval.evaluate()

      assert ctx.verdict == :fail, info(ctx)
    end

    test "003 - ptr domain spec must be valid" do
      sender = "someone@example.com"
      verdict = :permerror

      zonedata = """
      example.com TXT v=spf1 ptr:example.-com
      """

      ctx =
        Spf.Context.new(sender)
        |> Spf.DNS.load_lines(zonedata)
        |> Spf.Eval.evaluate()

      msg = "got #{ctx.verdict}, expected #{verdict}" <> info(ctx)
      assert ctx.verdict == verdict, msg
    end

    test "004 - ptr domain spec must be valid" do
      sender = "someone@example.com"
      verdict = :permerror

      zonedata = """
      example.com TXT v=spf1 ptr:example.123
      """

      ctx =
        Spf.Context.new(sender)
        |> Spf.DNS.load_lines(zonedata)
        |> Spf.Eval.evaluate()

      msg = "got #{ctx.verdict}, expected #{verdict}" <> info(ctx)
      assert ctx.verdict == verdict, msg
    end

    test "005 - exists domain spec must be valid" do
      sender = "someone@example.com"
      verdict = :permerror

      zonedata = """
      example.com TXT v=spf1 exists:example.123
      """

      ctx =
        Spf.Context.new(sender)
        |> Spf.DNS.load_lines(zonedata)
        |> Spf.Eval.evaluate()

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

      ctx =
        Spf.Context.new(sender)
        |> Spf.DNS.load_lines(zonedata)
        |> Spf.Eval.evaluate()

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

      ctx =
        Spf.Context.new(sender)
        |> Spf.DNS.load_lines(zonedata)
        |> Spf.Eval.evaluate()

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

      ctx =
        Spf.Context.new(sender)
        |> Spf.DNS.load_lines(zonedata)
        |> Spf.Eval.evaluate()

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
      x.example.com TXT %{d} says %{i} is not ok
      """

      ctx =
        Spf.Context.new(sender)
        |> Spf.DNS.load_lines(zonedata)
        |> Spf.Eval.evaluate()

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

      ctx =
        Spf.Context.new(sender)
        |> Spf.DNS.load_lines(zonedata)
        |> Spf.Eval.evaluate()

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

      ctx =
        Spf.Context.new(sender)
        |> Spf.DNS.load_lines(zonedata)
        |> Spf.Eval.evaluate()

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

      ctx =
        Spf.Context.new(sender)
        |> Spf.DNS.load_lines(zonedata)
        |> Spf.Eval.evaluate()

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

      ctx =
        Spf.Context.new(sender)
        |> Spf.DNS.load_lines(zonedata)
        |> Spf.Eval.evaluate()

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

      ctx =
        Spf.Context.new(sender)
        |> Spf.DNS.load_lines(zonedata)
        |> Spf.Eval.evaluate()

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

      ctx =
        Spf.Context.new(sender)
        |> Spf.DNS.load_lines(zonedata)
        |> Spf.Eval.evaluate()

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

      ctx =
        Spf.Context.new(sender)
        |> Spf.DNS.load_lines(zonedata)
        |> Spf.Eval.evaluate()

      msg =
        "got #{ctx.verdict}, expected #{verdict}" <> info(ctx) <> "\nctx.map\n#{inspect(ctx.map)}"

      assert ctx.verdict == verdict, msg
    end
  end
end
