defmodule Spf.ParserTest do
  use ExUnit.Case
  doctest Spf.Parser, import: true

  @context Spf.Context.new("example.com")

  defp parse(spf) do
    # returns an "example.com"-context with parsed spf string
    @context
    |> Map.put(:spf, spf)
    |> Spf.Parser.parse()
  end

  describe "edge cases" do
    @describetag :parser_edge_cases
    test "01 - txt too long" do
      filler = String.duplicate("ip4:255.255.255.255 ", 200)
      spf = "v=spf1 #{filler}-all"

      ctx =
        Spf.Context.new("example.com")
        |> Map.put(:spf, spf)
        |> Spf.Parser.parse()

      msg = List.first(ctx.msg)
      assert :warn == elem(msg, 2)
      assert String.contains?(elem(msg, 3), "TXT length")
    end
  end

  describe "all-mechanism" do
    @describetag :parse_all

    test "01 - all" do
      assert [{:all, [?+], 0..2}] == parse("all").ast
      assert [{:all, [?+], 0..3}] == parse("+all").ast
      assert [{:all, [?-], 0..3}] == parse("-all").ast
      assert [{:all, [?~], 0..3}] == parse("~all").ast
      assert [{:all, [??], 0..3}] == parse("?all").ast
    end

    test "02 - all with errors" do
      # note: all= is actually a legal, but unusual, unknown modifier
      assert :syntax_error == parse("all:").error
      assert :syntax_error == parse("all/24").error
      assert :syntax_error == parse("all//64").error
      assert nil == parse("all=something").error
    end
  end

  describe "a-mechanism" do
    @describetag :parse_a

    test "01 - a" do
      assert [{:a, [?+, "example.com", [32, 128]], 0..0}] == parse("a").ast
      assert [{:a, [?+, "example.com", [32, 128]], 0..1}] == parse("+a").ast
      assert [{:a, [?-, "example.com", [32, 128]], 0..1}] == parse("-a").ast
      assert [{:a, [?~, "example.com", [32, 128]], 0..1}] == parse("~a").ast
      assert [{:a, [??, "example.com", [32, 128]], 0..1}] == parse("?a").ast
    end

    test "02 - a with domain" do
      assert [{:a, [?+, "b.example.com", [32, 128]], 0..14}] == parse("a:b.example.com").ast
    end

    test "03 - a with cidr" do
      assert [{:a, [?+, "example.com", [24, 128]], 0..3}] == parse("a/24").ast
      assert [{:a, [?+, "example.com", [32, 64]], 0..4}] == parse("a//64").ast
      assert [{:a, [?+, "example.com", [24, 64]], 0..7}] == parse("a/24//64").ast
    end

    test "04 - a with domain and cidr" do
      assert [{:a, [?+, "b.example.com", [24, 128]], 0..17}] == parse("a:b.example.com/24").ast
    end

    test "05 - a with domain and cidr" do
      assert [{:a, [?+, "b.example.com", [32, 64]], 0..18}] == parse("a:b.example.com//64").ast
    end

    test "06 - a with domain and cidr" do
      assert [{:a, [?+, "b.example.com", [24, 64]], 0..21}] == parse("a:b.example.com/24//64").ast
    end

    test "07 - a with macros" do
      assert [{:a, [?+, "b.example.com", [24, 64]], 0..14}] == parse("a:b.%{d}/24//64").ast
      assert [{:a, [?+, "example.com", [24, 64]], 0..12}] == parse("a:%{d}/24//64").ast
      assert [{:a, [?+, "com.example", [24, 64]], 0..13}] == parse("a:%{dr}/24//64").ast
      assert [{:a, [?+, "com.example", [24, 64]], 0..21}] == parse("a:%{d1}.example/24//64").ast
    end

    test "08 - a with domain errors" do
      assert :syntax_error == parse("a:b.example.c%m").error
      assert :syntax_error == parse("a:b.example.-com").error
      assert :syntax_error == parse("a:b.example.com-").error
      assert :syntax_error == parse("a:b.example.123").error
      assert :syntax_error == parse("a:museum").error
      assert :syntax_error == parse("a:museum.").error
      assert :syntax_error == parse("a:").error
    end

    test "09 - a with cidr leading zeros" do
      assert :syntax_error == parse("a/024").error
    end

    test "10 - a with cidr errors" do
      assert :syntax_error == parse("a//064").error
    end
  end

  describe "mx-mechanism" do
    @describetag :parse_mx
    test "01 - mx" do
      assert [{:mx, [?+, "example.com", [32, 128]], 0..1}] == parse("mx").ast
      assert [{:mx, [?+, "example.com", [32, 128]], 0..2}] == parse("+mx").ast
      assert [{:mx, [?-, "example.com", [32, 128]], 0..2}] == parse("-mx").ast
      assert [{:mx, [?~, "example.com", [32, 128]], 0..2}] == parse("~mx").ast
      assert [{:mx, [??, "example.com", [32, 128]], 0..2}] == parse("?mx").ast
    end
  end

  describe "ip4-mechanism" do
    @describetag :parse_ip4

    test "01 - ip4" do
      assert [{:ip4, [?+, Pfx.new("1.1.1.1")], 0..10}] == parse("ip4:1.1.1.1").ast
      assert [{:ip4, [?+, Pfx.new("1.1.1.1")], 0..11}] == parse("+ip4:1.1.1.1").ast
      assert [{:ip4, [?-, Pfx.new("1.1.1.1")], 0..11}] == parse("-ip4:1.1.1.1").ast
      assert [{:ip4, [?~, Pfx.new("1.1.1.1")], 0..11}] == parse("~ip4:1.1.1.1").ast
      assert [{:ip4, [??, Pfx.new("1.1.1.1")], 0..11}] == parse("?ip4:1.1.1.1").ast
    end

    test "02 - ip4 with mask" do
      assert [{:ip4, [?+, Pfx.new("1.1.1.0/24")], 0..13}] == parse("ip4:1.1.1.0/24").ast
      assert [{:ip4, [?+, Pfx.new("1.1.1.1")], 0..13}] == parse("ip4:1.1.1.1/32").ast
      assert [{:ip4, [?+, Pfx.new("0.0.0.0/0")], 0..12}] == parse("ip4:1.1.1.1/0").ast
    end

    test "03 - ip4 with errors" do
      assert :syntax_error == parse("ip4:01.1.1.1/24").error, "leading zero"
      assert :syntax_error == parse("ip4:1.01.1.1/24").error, "leading zero"
      assert :syntax_error == parse("ip4:1.1.01.1/24").error, "leading zero"
      assert :syntax_error == parse("ip4:1.1.1.01/24").error, "leading zero"
      assert :syntax_error == parse("ip4:1.1.1.1/04").error, "leading zero"
      assert :syntax_error == parse("ip4:1.1.1.1/").error, "missing prefix length"
      assert :syntax_error == parse("ip4:1.1.1.1/33").error, "illegal prefix length"

      # weird stuff
      assert :syntax_error == parse("ip4").error
      assert :syntax_error == parse("ip4/24").error
      assert :syntax_error == parse("ip4:").error
      assert :syntax_error == parse("ip4:example.com").error, "not a prefix"
    end

    test "04 - missing digits" do
      assert :syntax_error == parse("ip4:1.1/24").error
      assert :syntax_error == parse("ip4:1.01.1/24").error
    end
  end

  describe "ip6-mechanism" do
    @describetag :parse_ip6

    test "01 - ip6" do
      assert [{:ip6, [?+, Pfx.new("2001:db8::1")], 0..14}] == parse("ip6:2001:db8::1").ast
      assert [{:ip6, [?+, Pfx.new("2001:db8::1")], 0..15}] == parse("+ip6:2001:db8::1").ast
      assert [{:ip6, [?-, Pfx.new("2001:db8::1")], 0..15}] == parse("-ip6:2001:db8::1").ast
      assert [{:ip6, [?~, Pfx.new("2001:db8::1")], 0..15}] == parse("~ip6:2001:db8::1").ast
      assert [{:ip6, [??, Pfx.new("2001:db8::1")], 0..15}] == parse("?ip6:2001:db8::1").ast
    end

    test "02 - ip6 with mask" do
      assert [{:ip6, [?+, Pfx.new("2001:db8::/64")], 0..16}] == parse("ip6:2001:db8::/64").ast
      assert [{:ip6, [?+, Pfx.new("2001:db8::1")], 0..18}] == parse("ip6:2001:db8::1/128").ast
      assert [{:ip6, [?+, Pfx.new("::/0")], 0..16}] == parse("ip6:2001:db8::1/0").ast
    end

    test "03 - ip6 with errors" do
      assert :syntax_error == parse("ip6:2001::db8::1/04").error, "leading zero"
      assert :syntax_error == parse("ip6:2001::db8::1/").error, "missing prefix length"
      assert :syntax_error == parse("ip6:2001::db8::1/129").error, "illegal prefix length"

      # weird stuff
      assert :syntax_error == parse("ip6").error
      assert :syntax_error == parse("ip6//64").error
      assert :syntax_error == parse("ip6:").error
      assert :syntax_error == parse("ip6:example.com").error
    end
  end

  describe "ptr-mechanism" do
    @describetag :parse_ptr

    test "01 - ptr" do
      assert [{:ptr, [?+, "example.com"], 0..2}] == parse("ptr").ast
      assert [{:ptr, [?+, "example.com"], 0..3}] == parse("+ptr").ast
      assert [{:ptr, [?-, "example.com"], 0..3}] == parse("-ptr").ast
      assert [{:ptr, [?~, "example.com"], 0..3}] == parse("~ptr").ast
      assert [{:ptr, [??, "example.com"], 0..3}] == parse("?ptr").ast
    end

    test "02 - ptr with domain" do
      assert [{:ptr, [?+, "example.com"], 0..7}] == parse("ptr:%{d}").ast
      assert [{:ptr, [?+, "example.com"], 0..8}] == parse("+ptr:%{d}").ast
      assert [{:ptr, [?-, "example.com"], 0..8}] == parse("-ptr:%{d}").ast
      assert [{:ptr, [?~, "example.com"], 0..8}] == parse("~ptr:%{d}").ast
      assert [{:ptr, [??, "example.com"], 0..8}] == parse("?ptr:%{d}").ast

      assert [{:ptr, [?+, "com.example"], 0..14}] == parse("ptr:com.example").ast
    end

    test "03 - ptr with errors" do
      assert :syntax_error == parse("ptr:").error
      assert :syntax_error == parse("ptr:").error
      assert :syntax_error == parse("ptr/24").error
      assert :syntax_error == parse("ptr//64").error
      assert :syntax_error == parse("ptr:%d").error
      assert :syntax_error == parse("ptr:%{z}").error
      assert :syntax_error == parse("ptr:example.c%m").error
      assert :syntax_error == parse("ptr:example.123").error
    end
  end

  describe "include-mechanism" do
    @describetag :parse_include

    test "01 - include" do
      assert [{:include, [?+, "example.com"], 0..11}] == parse("include:%{d}").ast
      assert [{:include, [?+, "example.com"], 0..12}] == parse("+include:%{d}").ast
      assert [{:include, [?-, "example.com"], 0..12}] == parse("-include:%{d}").ast
      assert [{:include, [?~, "example.com"], 0..12}] == parse("~include:%{d}").ast
      assert [{:include, [??, "example.com"], 0..12}] == parse("?include:%{d}").ast

      assert [{:include, [?+, "com.example"], 0..18}] == parse("include:com.example").ast
    end

    test "02 - include with errors" do
      assert :syntax_error == parse("include:").error
      assert :syntax_error == parse("include:%{z}").error
      assert :syntax_error == parse("include:example.com/24").error
      assert :syntax_error == parse("include:example.c%m").error
      assert :syntax_error == parse("include:example.-com").error
      assert :syntax_error == parse("include:example.com-").error
      assert :syntax_error == parse("include:example.123").error
    end
  end

  describe "exists-mechanism" do
    @describetag :parse_exists

    test "01 - exists" do
      assert [{:exists, [?+, "example.com"], 0..10}] == parse("exists:%{d}").ast
      assert [{:exists, [?+, "example.com"], 0..11}] == parse("+exists:%{d}").ast
      assert [{:exists, [?-, "example.com"], 0..11}] == parse("-exists:%{d}").ast
      assert [{:exists, [?~, "example.com"], 0..11}] == parse("~exists:%{d}").ast
      assert [{:exists, [??, "example.com"], 0..11}] == parse("?exists:%{d}").ast

      assert [{:exists, [?+, "com.example"], 0..17}] == parse("exists:com.example").ast
    end

    test "02 - exists with errors" do
      assert :syntax_error == parse("exists:").error
      assert :syntax_error == parse("exists:%{bad}").error
      assert :syntax_error == parse("exists:example.com/24").error
      assert :syntax_error == parse("exists:example.c%m").error
      assert :syntax_error == parse("exists:example.-com").error
      assert :syntax_error == parse("exists:example.com-").error
      assert :syntax_error == parse("exists:example.123").error
    end

    test "03 - exists with some macro's" do
      assert [{:exists, [?+, "example.com"], 0..10}] == parse("exists:%{s}").ast

      ctx =
        Spf.Context.new("example.com")
        |> Map.put(:dns, %{
          {"example.com", :a} => ["1.2.3.4"],
          {"4.3.2.1.in-addr.arpa", :ptr} => {:error, :nxdomain}
        })
        |> Map.put(:spf, "exists:%{p}")

      assert [{:exists, [?+, "unknown"], 0..10}] == Spf.Parser.parse(ctx).ast
    end
  end

  describe "redirect-modifier" do
    @describetag :parse_redirect

    test "01 - redirect" do
      assert [{:redirect, ["example.com"], 0..12}] == parse("redirect=%{d}").ast
      assert [{:redirect, ["example.com"], 0..19}] == parse("redirect=example.com").ast
      assert [{:redirect, ["example.1-1"], 0..19}] == parse("redirect=example.1-1").ast
      assert [{:redirect, ["example.b64"], 0..19}] == parse("redirect=example.b64").ast
      assert [{:redirect, ["example.6b4"], 0..19}] == parse("redirect=example.6b4").ast
      assert [{:redirect, ["example.64b"], 0..19}] == parse("redirect=example.64b").ast
    end

    test "02 - redirect with errors" do
      assert :syntax_error == parse("redirect").error
      assert :syntax_error == parse("redirect:example.com").error
      assert :syntax_error == parse("redirect:e%ample.com").error
      assert :syntax_error == parse("redirect:example.-com").error
      assert :syntax_error == parse("redirect:example.com-").error
      assert :syntax_error == parse("redirect:example.123").error
      assert :syntax_error == parse("redirect=example.com/24").error
    end
  end

  describe "exp-modifier" do
    @describetag :parse_exp
    # note: exp token is stored under :explain in context, not in the ast

    test "01 - exp" do
      assert {:exp, ["example.com"], 0..14} == parse("exp=example.com").explain
      assert {:exp, ["example.1-1"], 0..14} == parse("exp=example.1-1").explain
      assert {:exp, ["example.b64"], 0..14} == parse("exp=example.b64").explain
      assert {:exp, ["example.6b4"], 0..14} == parse("exp=example.6b4").explain
      assert {:exp, ["example.64b"], 0..14} == parse("exp=example.64b").explain
      assert {:exp, ["example.com"], 0..7} == parse("exp=%{d}").explain
    end

    test "02 - exp with errors" do
      assert :syntax_error == parse("exp").error
      assert :syntax_error == parse("exp=").error
      assert :syntax_error == parse("exp:example.com").error
      assert :syntax_error == parse("exp:e%ample.com").error
      assert :syntax_error == parse("exp:example.-com").error
      assert :syntax_error == parse("exp:example.com-").error
      assert :syntax_error == parse("exp:example.123").error
      assert :syntax_error == parse("exp=example.com/24").error
    end

    test "03 - explain string with errors" do
      ctx =
        Spf.Context.new("example.com")
        |> Map.put(:explain_string, "%{x} is an error")
        |> Spf.Parser.explain()

      assert "" == ctx.explanation
    end

    test "04 - explain string with r-macro" do
      ctx =
        Spf.Context.new("example.com")
        |> Map.put(:explain_string, "%{r} is unknown")
        |> Spf.Parser.explain()

      assert "unknown is unknown" == ctx.explanation
    end

    test "05 - explain string with t-macro" do
      ctx =
        Spf.Context.new("example.com")
        |> Map.put(:t0, 42)
        |> Map.put(:explain_string, "%{t} is the meaning of life")
        |> Spf.Parser.explain()

      assert "42 is the meaning of life" == ctx.explanation
    end

    test "06 - explain is empty" do
      # this is a bit artificial, since in an `exp=string`, string can never be
      # an empty string

      ctx =
        Spf.Context.new("example.com")
        |> Map.put(:explain, "")
        |> Spf.Parser.explain()

      assert "" == ctx.explanation
    end
  end

  describe "unknown-modifier" do
    @describetag :parse_unknown
    # unknown-modifier = name "=" macro-string
    # macro-string     = *( macro-expand / macro-literal )
    # ; macro-string can be empty

    test "01 - unknown" do
      # note: the parser does not include unknown modifiers in the ast
      ctx = parse("unknown=%{d}")
      assert nil == ctx.error
      assert [] == ctx.ast

      ctx = parse("unknown=a-macro-string")
      assert nil == ctx.error
      assert [] == ctx.ast

      ctx = parse("unknown=")
      assert nil == ctx.error
      assert [] == ctx.ast
    end

    test "02 - unknown with errors" do
      # notes:
      # - unknown modifiers still can have syntax errors
      # - unknown modifiers cannot use c,r,t-macros
      assert :syntax_error == parse("unknown=%{z}").error
      assert :syntax_error == parse("unknown=%z").error
      assert :syntax_error == parse("unknown=%{c}").error
      assert :syntax_error == parse("unknown=%{r}").error
      assert :syntax_error == parse("unknown=%{t}").error
    end

    test "03 - unknown modifier can have mechanism names" do
      assert nil == parse("a=something").error
      assert nil == parse("all=something").error
      assert nil == parse("mx=something").error
      assert nil == parse("ip4=something").error
      assert nil == parse("ip6=something").error
      assert nil == parse("ptr=something").error
      assert nil == parse("include=something").error
      assert nil == parse("exists=something").error
    end
  end

  describe "version" do
    @describetag :version
    test "01 - normal version" do
      assert [{:version, [1], 0..5}] == parse("v=spf1").spf_tokens
    end

    test "01 - abnormal version" do
      assert [{:version, [42], 0..6}] == parse("v=spf42").spf_tokens
    end
  end

  describe "whitespace" do
    @describetag :whitespace
    test "01 - whitespace" do
      assert [{:whitespace, [" "], 0..0}] == parse(" ").spf_tokens
    end

    test "02 - multiple whitespace" do
      assert [{:whitespace, ["  "], 0..1}] == parse("  ").spf_tokens
    end

    test "03 - tab as whitespace" do
      assert [{:whitespace, ["\t"], 0..0}] == parse("\t").spf_tokens
    end

    test "04 - mix of space and tab as whitespace" do
      assert [{:whitespace, [" \t "], 0..2}] == parse(" \t ").spf_tokens
    end
  end
end
