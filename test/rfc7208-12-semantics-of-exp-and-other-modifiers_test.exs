defmodule Rfc7208.Section12Test do
  use ExUnit.Case

  # Generated by mix rfc7208.testsuite
  # Usage:
  # % mix test
  # % mix test --only set:12
  # % mix test --only tst:12.y where y is in [0..22]

  describe "rfc7208-12-semantics-of-exp-and-other-modifiers" do
    @tag set: "12"
    @tag tst: "12.0"
    test "12.0 default-modifier-obsolete" do
      # spec 6/3 - Semantics of exp and other modifiers - default-modifier-obsolete

      ctx =
        Spf.check("foo@e19.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-12-semantics-of-exp-and-other-modifiers.zonedata"
        )

      assert to_string(ctx.verdict) in ["neutral"]
      assert ctx.explanation == ""
    end

    @tag set: "12"
    @tag tst: "12.1"
    test "12.1 default-modifier-obsolete2" do
      # spec 6/3 - Semantics of exp and other modifiers - default-modifier-obsolete2

      ctx =
        Spf.check("foo@e20.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-12-semantics-of-exp-and-other-modifiers.zonedata"
        )

      assert to_string(ctx.verdict) in ["neutral"]
      assert ctx.explanation == ""
    end

    @tag set: "12"
    @tag tst: "12.2"
    test "12.2 dorky-sentinel" do
      # spec 7.1/6 - Semantics of exp and other modifiers - dorky-sentinel

      ctx =
        Spf.check("Macro Error@e8.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-12-semantics-of-exp-and-other-modifiers.zonedata"
        )

      assert to_string(ctx.verdict) in ["fail"]
      assert ctx.explanation == "Macro Error in implementation"
    end

    @tag set: "12"
    @tag tst: "12.3"
    test "12.3 empty-modifier-name" do
      # spec A/3 - Semantics of exp and other modifiers - empty-modifier-name

      ctx =
        Spf.check("foo@e6.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-12-semantics-of-exp-and-other-modifiers.zonedata"
        )

      assert to_string(ctx.verdict) in ["permerror"]
      assert ctx.explanation == ""
    end

    @tag set: "12"
    @tag tst: "12.4"
    test "12.4 exp-dns-error" do
      # spec 6.2/4 - Semantics of exp and other modifiers - exp-dns-error

      ctx =
        Spf.check("foo@e21.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-12-semantics-of-exp-and-other-modifiers.zonedata"
        )

      assert to_string(ctx.verdict) in ["fail"]
      assert ctx.explanation == ""
    end

    @tag set: "12"
    @tag tst: "12.5"
    test "12.5 exp-empty-domain" do
      # spec 6.2/4 - Semantics of exp and other modifiers - exp-empty-domain

      ctx =
        Spf.check("foo@e12.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-12-semantics-of-exp-and-other-modifiers.zonedata"
        )

      assert to_string(ctx.verdict) in ["permerror"]
      assert ctx.explanation == ""
    end

    @tag set: "12"
    @tag tst: "12.6"
    test "12.6 exp-multiple-txt" do
      # spec 6.2/4 - Semantics of exp and other modifiers - exp-multiple-txt

      ctx =
        Spf.check("foo@e11.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-12-semantics-of-exp-and-other-modifiers.zonedata"
        )

      assert to_string(ctx.verdict) in ["fail"]
      assert ctx.explanation == ""
    end

    @tag set: "12"
    @tag tst: "12.7"
    test "12.7 exp-no-txt" do
      # spec 6.2/4 - Semantics of exp and other modifiers - exp-no-txt

      ctx =
        Spf.check("foo@e22.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-12-semantics-of-exp-and-other-modifiers.zonedata"
        )

      assert to_string(ctx.verdict) in ["fail"]
      assert ctx.explanation == ""
    end

    @tag set: "12"
    @tag tst: "12.8"
    test "12.8 exp-syntax-error" do
      # spec 6.2/1 - Semantics of exp and other modifiers - exp-syntax-error

      ctx =
        Spf.check("foo@e16.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-12-semantics-of-exp-and-other-modifiers.zonedata"
        )

      assert to_string(ctx.verdict) in ["permerror"]
      assert ctx.explanation == ""
    end

    @tag set: "12"
    @tag tst: "12.9"
    test "12.9 exp-twice" do
      # spec 6/2 - Semantics of exp and other modifiers - exp-twice

      ctx =
        Spf.check("foo@e14.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-12-semantics-of-exp-and-other-modifiers.zonedata"
        )

      assert to_string(ctx.verdict) in ["permerror"]
      assert ctx.explanation == ""
    end

    @tag set: "12"
    @tag tst: "12.10"
    test "12.10 exp-void" do
      # spec 4.6.4/1, 6/2 - Semantics of exp and other modifiers - exp-void

      ctx =
        Spf.check("foo@e23.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-12-semantics-of-exp-and-other-modifiers.zonedata"
        )

      assert to_string(ctx.verdict) in ["fail"]
      assert ctx.explanation == ""
    end

    @tag set: "12"
    @tag tst: "12.11"
    test "12.11 explanation-syntax-error" do
      # spec 6.2/4 - Semantics of exp and other modifiers - explanation-syntax-error

      ctx =
        Spf.check("foo@e13.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-12-semantics-of-exp-and-other-modifiers.zonedata"
        )

      assert to_string(ctx.verdict) in ["fail"]
      assert ctx.explanation == ""
    end

    @tag set: "12"
    @tag tst: "12.12"
    test "12.12 include-ignores-exp" do
      # spec 6.2/13 - Semantics of exp and other modifiers - include-ignores-exp

      ctx =
        Spf.check("foo@e7.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-12-semantics-of-exp-and-other-modifiers.zonedata"
        )

      assert to_string(ctx.verdict) in ["fail"]
      assert ctx.explanation == "Correct!"
    end

    @tag set: "12"
    @tag tst: "12.13"
    test "12.13 invalid-modifier" do
      # spec A/3 - Semantics of exp and other modifiers - invalid-modifier

      ctx =
        Spf.check("foo@e5.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-12-semantics-of-exp-and-other-modifiers.zonedata"
        )

      assert to_string(ctx.verdict) in ["permerror"]
      assert ctx.explanation == ""
    end

    @tag set: "12"
    @tag tst: "12.14"
    test "12.14 non-ascii-exp" do
      # spec 6.2/5 - Semantics of exp and other modifiers - non-ascii-exp

      ctx =
        Spf.check("foobar@nonascii.example.com",
          helo: "hosed",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-12-semantics-of-exp-and-other-modifiers.zonedata"
        )

      assert to_string(ctx.verdict) in ["fail"]
      assert ctx.explanation == ""
    end

    @tag set: "12"
    @tag tst: "12.15"
    test "12.15 redirect-cancels-exp" do
      # spec 6.2/13 - Semantics of exp and other modifiers - redirect-cancels-exp

      ctx =
        Spf.check("foo@e1.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-12-semantics-of-exp-and-other-modifiers.zonedata"
        )

      assert to_string(ctx.verdict) in ["fail"]
      assert ctx.explanation == ""
    end

    @tag set: "12"
    @tag tst: "12.16"
    test "12.16 redirect-cancels-prior-exp" do
      # spec 6.2/13 - Semantics of exp and other modifiers - redirect-cancels-prior-exp

      ctx =
        Spf.check("foo@e3.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-12-semantics-of-exp-and-other-modifiers.zonedata"
        )

      assert to_string(ctx.verdict) in ["fail"]
      assert ctx.explanation == "See me."
    end

    @tag set: "12"
    @tag tst: "12.17"
    test "12.17 redirect-empty-domain" do
      # spec 6.2/4 - Semantics of exp and other modifiers - redirect-empty-domain

      ctx =
        Spf.check("foo@e18.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-12-semantics-of-exp-and-other-modifiers.zonedata"
        )

      assert to_string(ctx.verdict) in ["permerror"]
      assert ctx.explanation == ""
    end

    @tag set: "12"
    @tag tst: "12.18"
    test "12.18 redirect-none" do
      # spec 6.1/4 - Semantics of exp and other modifiers - redirect-none

      ctx =
        Spf.check("foo@e10.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-12-semantics-of-exp-and-other-modifiers.zonedata"
        )

      assert to_string(ctx.verdict) in ["permerror"]
      assert ctx.explanation == ""
    end

    @tag set: "12"
    @tag tst: "12.19"
    test "12.19 redirect-syntax-error" do
      # spec 6.1/2 - Semantics of exp and other modifiers - redirect-syntax-error

      ctx =
        Spf.check("foo@e17.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-12-semantics-of-exp-and-other-modifiers.zonedata"
        )

      assert to_string(ctx.verdict) in ["permerror"]
      assert ctx.explanation == ""
    end

    @tag set: "12"
    @tag tst: "12.20"
    test "12.20 redirect-twice" do
      # spec 6/2 - Semantics of exp and other modifiers - redirect-twice

      ctx =
        Spf.check("foo@e15.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-12-semantics-of-exp-and-other-modifiers.zonedata"
        )

      assert to_string(ctx.verdict) in ["permerror"]
      assert ctx.explanation == ""
    end

    @tag set: "12"
    @tag tst: "12.21"
    test "12.21 two-exp-records" do
      # spec 6.2/4 - Semantics of exp and other modifiers - two-exp-records

      ctx =
        Spf.check("foobar@tworecs.example.com",
          helo: "hosed",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-12-semantics-of-exp-and-other-modifiers.zonedata"
        )

      assert to_string(ctx.verdict) in ["fail"]
      assert ctx.explanation == ""
    end

    @tag set: "12"
    @tag tst: "12.22"
    test "12.22 unknown-modifier-syntax" do
      # spec A/3 - Semantics of exp and other modifiers - unknown-modifier-syntax

      ctx =
        Spf.check("foo@e9.example.com",
          helo: "mail.example.com",
          ip: "1.2.3.4",
          dns: "test/zones/rfc7208-12-semantics-of-exp-and-other-modifiers.zonedata"
        )

      assert to_string(ctx.verdict) in ["permerror"]
      assert ctx.explanation == ""
    end
  end
end
