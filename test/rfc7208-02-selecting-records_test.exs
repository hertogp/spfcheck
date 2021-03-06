defmodule Rfc7208.Section2Test do
  use ExUnit.Case

  # Generated by mix rfc7208.testsuite
  # Usage:
  # % mix test
  # % mix test --only set:2
  # % mix test --only tst:2.y where y is in [0..9]

  describe "rfc7208-02-selecting-records" do
    @tag set: "2"
    @tag tst: "2.0"
    test "2.0 case-insensitive" do
      # spec 4.5/6 - Selecting records - case-insensitive
      _cli = """
      spfcheck foo@example9.com -i 1.2.3.4 -h mail.example1.com -v 5 \
       -d test/zones/rfc7208-02-selecting-records.zonedata
      """

      ctx =
        Spf.check("foo@example9.com",
          helo: "mail.example1.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-02-selecting-records.zonedata"
        )

      assert to_string(ctx.verdict) in ["softfail"]
      assert ctx.explanation == ""
    end

    @tag set: "2"
    @tag tst: "2.1"
    test "2.1 empty" do
      # spec 4.5/4 - Selecting records - empty
      _cli = """
      spfcheck foo@example1.com -i 1.2.3.4 -h mail1.example1.com -v 5 \
       -d test/zones/rfc7208-02-selecting-records.zonedata
      """

      ctx =
        Spf.check("foo@example1.com",
          helo: "mail1.example1.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-02-selecting-records.zonedata"
        )

      assert to_string(ctx.verdict) in ["neutral"]
      assert ctx.explanation == ""
    end

    @tag set: "2"
    @tag tst: "2.2"
    test "2.2 multispf1" do
      # spec 4.5/6 - Selecting records - multispf1
      _cli = """
      spfcheck foo@example7.com -i 1.2.3.4 -h mail.example1.com -v 5 \
       -d test/zones/rfc7208-02-selecting-records.zonedata
      """

      ctx =
        Spf.check("foo@example7.com",
          helo: "mail.example1.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-02-selecting-records.zonedata"
        )

      assert to_string(ctx.verdict) in ["permerror", "fail"]
      assert ctx.explanation == ""
    end

    @tag set: "2"
    @tag tst: "2.3"
    test "2.3 multispf2" do
      # spec 4.5/6 - Selecting records - multispf2
      _cli = """
      spfcheck foo@example8.com -i 1.2.3.4 -h mail.example1.com -v 5 \
       -d test/zones/rfc7208-02-selecting-records.zonedata
      """

      ctx =
        Spf.check("foo@example8.com",
          helo: "mail.example1.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-02-selecting-records.zonedata"
        )

      assert to_string(ctx.verdict) in ["pass"]
      assert ctx.explanation == ""
    end

    @tag set: "2"
    @tag tst: "2.4"
    test "2.4 multitxt1" do
      # spec 4.5/5 - Selecting records - multitxt1
      _cli = """
      spfcheck foo@example5.com -i 1.2.3.4 -h mail.example1.com -v 5 \
       -d test/zones/rfc7208-02-selecting-records.zonedata
      """

      ctx =
        Spf.check("foo@example5.com",
          helo: "mail.example1.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-02-selecting-records.zonedata"
        )

      assert to_string(ctx.verdict) in ["permerror"]
      assert ctx.explanation == ""
    end

    @tag set: "2"
    @tag tst: "2.5"
    test "2.5 multitxt2" do
      # spec 4.5/6 - Selecting records - multitxt2
      _cli = """
      spfcheck foo@example6.com -i 1.2.3.4 -h mail.example1.com -v 5 \
       -d test/zones/rfc7208-02-selecting-records.zonedata
      """

      ctx =
        Spf.check("foo@example6.com",
          helo: "mail.example1.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-02-selecting-records.zonedata"
        )

      assert to_string(ctx.verdict) in ["permerror"]
      assert ctx.explanation == ""
    end

    @tag set: "2"
    @tag tst: "2.6"
    test "2.6 nospace1" do
      # spec 4.5/4 - Selecting records - nospace1
      _cli = """
      spfcheck foo@example2.com -i 1.2.3.4 -h mail.example1.com -v 5 \
       -d test/zones/rfc7208-02-selecting-records.zonedata
      """

      ctx =
        Spf.check("foo@example2.com",
          helo: "mail.example1.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-02-selecting-records.zonedata"
        )

      assert to_string(ctx.verdict) in ["none"]
      assert ctx.explanation == ""
    end

    @tag set: "2"
    @tag tst: "2.7"
    test "2.7 nospace2" do
      # spec 4.5/4 - Selecting records - nospace2
      _cli = """
      spfcheck foo@example3.com -i 1.2.3.4 -h mail.example1.com -v 5 \
       -d test/zones/rfc7208-02-selecting-records.zonedata
      """

      ctx =
        Spf.check("foo@example3.com",
          helo: "mail.example1.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-02-selecting-records.zonedata"
        )

      assert to_string(ctx.verdict) in ["pass"]
      assert ctx.explanation == ""
    end

    @tag set: "2"
    @tag tst: "2.8"
    test "2.8 nospf" do
      # spec 4.5/7 - Selecting records - nospf
      _cli = """
      spfcheck foo@mail.example1.com -i 1.2.3.4 -h mail.example1.com -v 5 \
       -d test/zones/rfc7208-02-selecting-records.zonedata
      """

      ctx =
        Spf.check("foo@mail.example1.com",
          helo: "mail.example1.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-02-selecting-records.zonedata"
        )

      assert to_string(ctx.verdict) in ["none"]
      assert ctx.explanation == ""
    end

    @tag set: "2"
    @tag tst: "2.9"
    test "2.9 spfoverride" do
      # spec 4.5/5 - Selecting records - spfoverride
      _cli = """
      spfcheck foo@example4.com -i 1.2.3.4 -h mail.example1.com -v 5 \
       -d test/zones/rfc7208-02-selecting-records.zonedata
      """

      ctx =
        Spf.check("foo@example4.com",
          helo: "mail.example1.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-02-selecting-records.zonedata"
        )

      assert to_string(ctx.verdict) in ["fail"]
      assert ctx.explanation == ""
    end
  end
end
