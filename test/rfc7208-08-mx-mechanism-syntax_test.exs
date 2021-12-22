defmodule Rfc7208.Section8Test do
  use ExUnit.Case

  # Generated by mix rfc7208.testsuite
  # Usage:
  # % mix test
  # % mix test --only set:8
  # % mix test --only tst:8.y where y is in [0..20]

  describe "rfc7208-08-mx-mechanism-syntax" do
    @tag set: "8"
    @tag tst: "8.0"
    test "8.0 mx-bad-cidr4" do
      # spec 5.4/2 - MX mechanism syntax - mx-bad-cidr4

      ctx =
        Spf.check("foo@e6a.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-08-mx-mechanism-syntax.zonedata"
        )

      assert to_string(ctx.verdict) in ["permerror"]
      assert ctx.explanation == ""
    end

    @tag set: "8"
    @tag tst: "8.1"
    test "8.1 mx-bad-cidr6" do
      # spec 5.4/2 - MX mechanism syntax - mx-bad-cidr6

      ctx =
        Spf.check("foo@e7.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-08-mx-mechanism-syntax.zonedata"
        )

      assert to_string(ctx.verdict) in ["permerror"]
      assert ctx.explanation == ""
    end

    @tag set: "8"
    @tag tst: "8.2"
    test "8.2 mx-bad-domain" do
      # spec 7.1/2 - MX mechanism syntax - mx-bad-domain

      ctx =
        Spf.check("foo@e9.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-08-mx-mechanism-syntax.zonedata"
        )

      assert to_string(ctx.verdict) in ["permerror"]
      assert ctx.explanation == ""
    end

    @tag set: "8"
    @tag tst: "8.3"
    test "8.3 mx-bad-toplab" do
      # spec 7.1/2 - MX mechanism syntax - mx-bad-toplab

      ctx =
        Spf.check("foo@e12.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-08-mx-mechanism-syntax.zonedata"
        )

      assert to_string(ctx.verdict) in ["permerror"]
      assert ctx.explanation == ""
    end

    @tag set: "8"
    @tag tst: "8.4"
    test "8.4 mx-cidr4-0" do
      # spec 5.4/3 - MX mechanism syntax - mx-cidr4-0

      ctx =
        Spf.check("foo@e2.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-08-mx-mechanism-syntax.zonedata"
        )

      assert to_string(ctx.verdict) in ["pass"]
      assert ctx.explanation == ""
    end

    @tag set: "8"
    @tag tst: "8.5"
    test "8.5 mx-cidr4-0-ip6" do
      # spec 5.4/3 - MX mechanism syntax - mx-cidr4-0-ip6

      ctx =
        Spf.check("foo@e2.example.com",
          helo: "mail.example.com",
          ip: "1234::1",
          dns: "test/zones/rfc7208-08-mx-mechanism-syntax.zonedata"
        )

      assert to_string(ctx.verdict) in ["fail"]
      assert ctx.explanation == ""
    end

    @tag set: "8"
    @tag tst: "8.6"
    test "8.6 mx-cidr6" do
      # spec 5.4/2 - MX mechanism syntax - mx-cidr6

      ctx =
        Spf.check("foo@e6.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-08-mx-mechanism-syntax.zonedata"
        )

      assert to_string(ctx.verdict) in ["fail"]
      assert ctx.explanation == ""
    end

    @tag set: "8"
    @tag tst: "8.7"
    test "8.7 mx-cidr6-0-ip4" do
      # spec 5.4/3 - MX mechanism syntax - mx-cidr6-0-ip4

      ctx =
        Spf.check("foo@e2a.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-08-mx-mechanism-syntax.zonedata"
        )

      assert to_string(ctx.verdict) in ["fail"]
      assert ctx.explanation == ""
    end

    @tag set: "8"
    @tag tst: "8.8"
    test "8.8 mx-cidr6-0-ip4mapped" do
      # spec 5.4/3 - MX mechanism syntax - mx-cidr6-0-ip4mapped

      ctx =
        Spf.check("foo@e2a.example.com",
          helo: "mail.example.com",
          ip: "::FFFF:1.2.3.4",
          dns: "test/zones/rfc7208-08-mx-mechanism-syntax.zonedata"
        )

      assert to_string(ctx.verdict) in ["fail"]
      assert ctx.explanation == ""
    end

    @tag set: "8"
    @tag tst: "8.9"
    test "8.9 mx-cidr6-0-ip6" do
      # spec 5.3/3 - MX mechanism syntax - mx-cidr6-0-ip6

      ctx =
        Spf.check("foo@e2a.example.com",
          helo: "mail.example.com",
          ip: "1234::1",
          dns: "test/zones/rfc7208-08-mx-mechanism-syntax.zonedata"
        )

      assert to_string(ctx.verdict) in ["pass"]
      assert ctx.explanation == ""
    end

    @tag set: "8"
    @tag tst: "8.10"
    test "8.10 mx-cidr6-0-nxdomain" do
      # spec 5.4/3 - MX mechanism syntax - mx-cidr6-0-nxdomain

      ctx =
        Spf.check("foo@e2b.example.com",
          helo: "mail.example.com",
          ip: "1234::1",
          dns: "test/zones/rfc7208-08-mx-mechanism-syntax.zonedata"
        )

      assert to_string(ctx.verdict) in ["fail"]
      assert ctx.explanation == ""
    end

    @tag set: "8"
    @tag tst: "8.11"
    test "8.11 mx-colon-domain" do
      # spec 7.1/2 - MX mechanism syntax - mx-colon-domain

      ctx =
        Spf.check("foo@e11.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-08-mx-mechanism-syntax.zonedata"
        )

      assert to_string(ctx.verdict) in ["pass"]
      assert ctx.explanation == ""
    end

    @tag set: "8"
    @tag tst: "8.12"
    test "8.12 mx-colon-domain-ip4mapped" do
      # spec 7.1/2 - MX mechanism syntax - mx-colon-domain-ip4mapped

      ctx =
        Spf.check("foo@e11.example.com",
          helo: "mail.example.com",
          ip: "::FFFF:1.2.3.4",
          dns: "test/zones/rfc7208-08-mx-mechanism-syntax.zonedata"
        )

      assert to_string(ctx.verdict) in ["pass"]
      assert ctx.explanation == ""
    end

    @tag set: "8"
    @tag tst: "8.13"
    test "8.13 mx-empty" do
      # spec 5.4/3 - MX mechanism syntax - mx-empty

      ctx =
        Spf.check("",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-08-mx-mechanism-syntax.zonedata"
        )

      assert to_string(ctx.verdict) in ["neutral"]
      assert ctx.explanation == ""
    end

    @tag set: "8"
    @tag tst: "8.14"
    test "8.14 mx-empty-domain" do
      # spec 5.2/1 - MX mechanism syntax - mx-empty-domain

      ctx =
        Spf.check("foo@e13.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-08-mx-mechanism-syntax.zonedata"
        )

      assert to_string(ctx.verdict) in ["permerror"]
      assert ctx.explanation == ""
    end

    @tag set: "8"
    @tag tst: "8.15"
    test "8.15 mx-implicit" do
      # spec 5.4/4 - MX mechanism syntax - mx-implicit

      ctx =
        Spf.check("foo@e4.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-08-mx-mechanism-syntax.zonedata"
        )

      assert to_string(ctx.verdict) in ["neutral"]
      assert ctx.explanation == ""
    end

    @tag set: "8"
    @tag tst: "8.16"
    test "8.16 mx-multi-ip1" do
      # spec 5.4/3 - MX mechanism syntax - mx-multi-ip1

      ctx =
        Spf.check("foo@e10.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-08-mx-mechanism-syntax.zonedata"
        )

      assert to_string(ctx.verdict) in ["pass"]
      assert ctx.explanation == ""
    end

    @tag set: "8"
    @tag tst: "8.17"
    test "8.17 mx-multi-ip2" do
      # spec 5.4/3 - MX mechanism syntax - mx-multi-ip2

      ctx =
        Spf.check("foo@e10.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-08-mx-mechanism-syntax.zonedata"
        )

      assert to_string(ctx.verdict) in ["pass"]
      assert ctx.explanation == ""
    end

    @tag set: "8"
    @tag tst: "8.18"
    test "8.18 mx-null" do
      # spec 7.1/2 - MX mechanism syntax - mx-null

      ctx =
        Spf.check("foo@e3.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.5",
          dns: "test/zones/rfc7208-08-mx-mechanism-syntax.zonedata"
        )

      assert to_string(ctx.verdict) in ["permerror"]
      assert ctx.explanation == ""
    end

    @tag set: "8"
    @tag tst: "8.19"
    test "8.19 mx-numeric-top-label" do
      # spec 7.1/2 - MX mechanism syntax - mx-numeric-top-label

      ctx =
        Spf.check("foo@e5.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-08-mx-mechanism-syntax.zonedata"
        )

      assert to_string(ctx.verdict) in ["permerror"]
      assert ctx.explanation == ""
    end

    @tag set: "8"
    @tag tst: "8.20"
    test "8.20 mx-nxdomain" do
      # spec 5.4/3 - MX mechanism syntax - mx-nxdomain

      ctx =
        Spf.check("foo@e1.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-08-mx-mechanism-syntax.zonedata"
        )

      assert to_string(ctx.verdict) in ["fail"]
      assert ctx.explanation == ""
    end
  end
end
