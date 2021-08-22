defmodule Spf.TokenTest do
  use ExUnit.Case
  import NimbleParsec

  # assertions
  # from https://elixirforum.com/t/trying-to-write-a-simple-nimble-parsec-parser/41344/4

  @mletters String.split("slodiphcrtvSLODIPHCRTV", "", trim: true)

  def charcode(charstr) when is_binary(charstr),
    do: String.to_charlist(charstr) |> List.first()

  describe "domain_spec() parses" do
    defparsecp(:domain_spec, Spf.Tokens.domain_spec())

    test "simple macros" do
      check = fn l, str ->
        assert domain_spec(str) ==
                 {:ok, [{:domain_spec, [{:expand, [charcode(l), 0, false, ["."]], 0..3}], 0..3}],
                  "", %{start1: 0, start2: 0}, {1, 0}, 4}
      end

      testcases = for l <- @mletters, do: {l, "%{#{l}}"}
      Enum.map(testcases, fn {l, str} -> check.(l, str) end)
    end

    test "macros with keep" do
      check = fn l, str ->
        assert domain_spec(str) ==
                 {:ok, [{:domain_spec, [{:expand, [charcode(l), 3, false, ["."]], 0..4}], 0..4}],
                  "", %{start1: 0, start2: 0}, {1, 0}, 5}
      end

      testcases = for l <- @mletters, do: {l, "%{#{l}3}"}
      Enum.map(testcases, fn {l, str} -> check.(l, str) end)
    end

    test "macros with reverse" do
      check = fn l, str ->
        assert domain_spec(str) ==
                 {:ok, [{:domain_spec, [{:expand, [charcode(l), 0, true, ["."]], 0..4}], 0..4}],
                  "", %{start1: 0, start2: 0}, {1, 0}, 5}
      end

      testcases = for l <- @mletters, do: {l, "%{#{l}r}"}
      Enum.map(testcases, fn {l, str} -> check.(l, str) end)
      # also uppercase R
      testcases = for l <- @mletters, do: {l, "%{#{l}R}"}
      Enum.map(testcases, fn {l, str} -> check.(l, str) end)
    end

    test "macros with keep and reverse" do
      check = fn l, str ->
        assert domain_spec(str) ==
                 {:ok, [{:domain_spec, [{:expand, [charcode(l), 9, true, ["."]], 0..5}], 0..5}],
                  "", %{start1: 0, start2: 0}, {1, 0}, 6}
      end

      testcases = for l <- @mletters, do: {l, "%{#{l}9r}"}
      Enum.map(testcases, fn {l, str} -> check.(l, str) end)
      # also uppercase R
      testcases = for l <- @mletters, do: {l, "%{#{l}9R}"}
      Enum.map(testcases, fn {l, str} -> check.(l, str) end)
    end

    test "macros with delimiters" do
      check = fn l, str ->
        assert domain_spec(str) ==
                 {:ok,
                  [
                    {:domain_spec,
                     [
                       {:expand, [charcode(l), 0, false, [".", "-", "+", ",", "/", "_", "="]],
                        0..10}
                     ], 0..10}
                  ], "", %{start1: 0, start2: 0}, {1, 0}, 11}
      end

      testcases = for l <- @mletters, do: {l, "%{#{l}.-+,/_=}"}
      Enum.map(testcases, fn {l, str} -> check.(l, str) end)
    end

    test "macro specials" do
      {:ok, [token], _, _, _, _} = domain_spec("%%")
      assert token == {:domain_spec, [{:expand, '%', 0..1}], 0..1}

      {:ok, [token], _, _, _, _} = domain_spec("%-")
      assert token == {:domain_spec, [{:expand, '-', 0..1}], 0..1}

      {:ok, [token], _, _, _, _} = domain_spec("%_")
      assert token == {:domain_spec, [{:expand, '_', 0..1}], 0..1}
    end

    test "macros with reverse and delimiters" do
      check = fn l, str ->
        assert domain_spec(str) ==
                 {:ok,
                  [
                    {:domain_spec,
                     [
                       {:expand, [charcode(l), 0, true, [".", "-", "+", ",", "/", "_", "="]],
                        0..11}
                     ], 0..11}
                  ], "", %{start1: 0, start2: 0}, {1, 0}, 12}
      end

      testcases = for l <- @mletters, do: {l, "%{#{l}r.-+,/_=}"}
      Enum.map(testcases, fn {l, str} -> check.(l, str) end)
      # also uppercase R
      testcases = for l <- @mletters, do: {l, "%{#{l}R.-+,/_=}"}
      Enum.map(testcases, fn {l, str} -> check.(l, str) end)
    end

    test "macros with keep, reverse and delimiters" do
      check = fn l, str ->
        assert domain_spec(str) ==
                 {:ok,
                  [
                    {:domain_spec,
                     [
                       {:expand, [charcode(l), 11, true, [".", "-", "+", ",", "/", "_", "="]],
                        0..13}
                     ], 0..13}
                  ], "", %{start1: 0, start2: 0}, {1, 0}, 14}
      end

      testcases = for l <- @mletters, do: {l, "%{#{l}11r.-+,/_=}"}
      Enum.map(testcases, fn {l, str} -> check.(l, str) end)
      # also uppercase R
      testcases = for l <- @mletters, do: {l, "%{#{l}11R.-+,/_=}"}
      Enum.map(testcases, fn {l, str} -> check.(l, str) end)
    end

    test "macros with keep, reverse, delims, literals and specials" do
      assert {:ok, [token], rest, _, _, _} = domain_spec("%{d2R.-}%-com/24")
      assert rest == "/24"

      assert token ==
               {:domain_spec,
                [
                  {:expand, [?d, 2, true, [".", "-"]], 0..7},
                  {:expand, '-', 8..9},
                  {:literal, "com", 10..12}
                ], 0..12}
    end

    test "macros but not a following dual_cidr" do
      {:ok, [token], rest, _, _, _} = domain_spec("%{d}.com/24")

      assert token ==
               {:domain_spec, [{:expand, [?d, 0, false, ["."]], 0..3}, {:literal, ".com", 4..7}],
                0..7}

      assert rest == "/24"

      {:ok, [_token], rest, _, _, _} = domain_spec("%{d}.com//128")
      assert rest == "//128"

      {:ok, [_token], rest, _, _, _} = domain_spec("%{d}.com/32//128")
      assert rest == "/32//128"

      {:ok, [_token], rest, _, _, _} = domain_spec("%{d}.c%-o%_m%%/32//128")
      assert rest == "/32//128"
    end
  end

  describe "dual_cidr() lexes" do
    defparsecp(:cidr, Spf.Tokens.dual_cidr())

    test "/24" do
      assert cidr("/24") == {:ok, [{:dual_cidr, [24, 128], 0..2}], "", %{start1: 0}, {1, 0}, 3}
    end

    test "//64" do
      assert cidr("//64") == {:ok, [{:dual_cidr, [32, 64], 0..3}], "", %{start1: 0}, {1, 0}, 4}
    end

    test "/24//64" do
      assert cidr("/24//64") == {:ok, [{:dual_cidr, [24, 64], 0..6}], "", %{start1: 0}, {1, 0}, 7}
    end

    test "/33//129" do
      # parser will validate prefix lengths, not the lexer
      assert cidr("/33//129") ==
               {:ok, [{:dual_cidr, [33, 129], 0..7}], "", %{start1: 0}, {1, 0}, 8}
    end
  end

  describe "whitespace() lexes" do
    defparsecp(:wspace, Spf.Tokens.whitespace())

    test "1 space" do
      assert wspace(" ") ==
               {:ok, [{:whitespace, [" "], 0..0}], "", %{start1: 0}, {1, 0}, 1}
    end

    test "1+ spaces" do
      assert wspace("   ") ==
               {:ok, [{:whitespace, ["   "], 0..2}], "", %{start1: 0}, {1, 0}, 3}
    end

    test "1+ tabs" do
      assert wspace("\t\t") ==
               {:ok, [{:whitespace, ["\t\t"], 0..1}], "", %{start1: 0}, {1, 0}, 2}
    end

    test "1+ (SP / TAB)" do
      assert wspace(" \t ") ==
               {:ok, [{:whitespace, [" \t "], 0..2}], "", %{start1: 0}, {1, 0}, 3}
    end
  end

  describe "a() lexes" do
    defparsec(:a, Spf.Tokens.a())

    test "a" do
      assert a("a") ==
               {:ok, [{:a, [?+, []], 0..0}], "", %{start: 0}, {1, 0}, 1}
    end

    test "a with cidr" do
      assert a("a/24") ==
               {:ok, [{:a, [?+, [{:dual_cidr, [24, 128], 1..3}]], 0..3}], "",
                %{start: 0, start1: 1}, {1, 0}, 4}
    end

    test "a with domain_spec" do
      assert a("a:%{d}") ==
               {:ok,
                [
                  {:a, [43, [{:domain_spec, [{:expand, [100, 0, false, ["."]], 2..5}], 2..5}]],
                   0..5}
                ], "", %{start: 0, start1: 2, start2: 2}, {1, 0}, 6}
    end

    test "a with domain_spec and ipv4 cidr" do
      assert a("a:%{d}/24") ==
               {:ok,
                [
                  {:a,
                   [
                     43,
                     [
                       {:domain_spec, [{:expand, [100, 0, false, ["."]], 2..5}], 2..5},
                       {:dual_cidr, [24, 128], 6..8}
                     ]
                   ], 0..8}
                ], "", %{start: 0, start1: 6, start2: 2}, {1, 0}, 9}
    end

    test "a with domain_spec and ipv6 cidr" do
      assert a("a:%{d}//64") ==
               {:ok,
                [
                  {:a,
                   [
                     43,
                     [
                       {:domain_spec, [{:expand, [100, 0, false, ["."]], 2..5}], 2..5},
                       {:dual_cidr, [32, 64], 6..9}
                     ]
                   ], 0..9}
                ], "", %{start: 0, start1: 6, start2: 2}, {1, 0}, 10}
    end

    test "a with domain_spec and dual cidr" do
      assert a("a:%{d}/24//64") ==
               {:ok,
                [
                  {:a,
                   [
                     43,
                     [
                       {:domain_spec, [{:expand, [100, 0, false, ["."]], 2..5}], 2..5},
                       {:dual_cidr, [24, 64], 6..12}
                     ]
                   ], 0..12}
                ], "", %{start: 0, start1: 6, start2: 2}, {1, 0}, 13}
    end

    test "a with qualifier, domain_spec and dual cidr" do
      testcases = for q <- ["+", "-", "~", "?"], do: {charcode(q), "#{q}a:%{d}/24//64"}

      check = fn q, str ->
        assert a(str) ==
                 {:ok,
                  [
                    {:a,
                     [
                       q,
                       [
                         {:domain_spec, [{:expand, [100, 0, false, ["."]], 3..6}], 3..6},
                         {:dual_cidr, [24, 64], 7..13}
                       ]
                     ], 0..13}
                  ], "", %{start: 0, start1: 7, start2: 3}, {1, 0}, 14}
      end

      Enum.map(testcases, fn {l, str} -> check.(l, str) end)
    end
  end

  describe "all() lexes" do
    defparsec(:all, Spf.Tokens.all())

    test "all with implicit  qualifier" do
      {:ok, [token], _, _, _, _} = all("all")
      assert token == {:all, [?+], 0..2}
    end

    test "all with qualifier" do
      testcases = for q <- ["+", "-", "~", "?"], do: {charcode(q), "#{q}all"}

      check = fn q, str ->
        assert all(str) == {:ok, [{:all, [q], 0..3}], "", %{start: 0}, {1, 0}, 4}
      end

      Enum.map(testcases, fn {l, str} -> check.(l, str) end)
    end
  end

  describe "exists() lexes" do
    defparsec(:exists, Spf.Tokens.exists())

    test "its domain_spec" do
      {:ok, [token], _, _, _, _} = exists("exists:%{d1R-}.com")

      assert token ==
               {:exists,
                [
                  ?+,
                  {:domain_spec,
                   [
                     {:expand, [?d, 1, true, ["-"]], 7..13},
                     {:literal, ".com", 14..17}
                   ], 7..17}
                ], 0..17}
    end
  end

  describe "include() lexes" do
    defparsec(:include, Spf.Tokens.include())

    test "its domain_spec" do
      {:ok, [token], _, _, _, _} = include("include:spf.example.com")

      assert token ==
               {:include,
                [
                  ?+,
                  {:domain_spec,
                   [
                     {:literal, "spf.example.com", 8..22}
                   ], 8..22}
                ], 0..22}
    end
  end

  describe "ip4() lexes" do
    defparsec(:ip4, Spf.Tokens.ip4())

    test "an address" do
      {:ok, [token], _, _, _, _} = ip4("ip4:1.2.3.4")
      assert token == {:ip4, [?+, "1.2.3.4"], 0..10}
    end

    test "a prefix" do
      {:ok, [token], _, _, _, _} = ip4("ip4:1.2.3.4/32")
      assert token == {:ip4, [?+, "1.2.3.4/32"], 0..13}
    end

    test "anything really" do
      # Note: ip4 cheats and lexes any non-spaces since ip4 parsing is done
      # later on by the Parser.
      {:ok, [token], _, _, _, _} = ip4("ip4:a.b.c.d/xy")
      assert token == {:ip4, [?+, "a.b.c.d/xy"], 0..13}
    end
  end

  describe "ip6() lexes" do
    defparsec(:ip6, Spf.Tokens.ip6())

    test "an address" do
      {:ok, [token], _, _, _, _} = ip6("ip6:2001::4")
      assert token == {:ip6, [?+, "2001::4"], 0..10}
    end

    test "a prefix" do
      {:ok, [token], _, _, _, _} = ip6("ip6:2001::/32")
      assert token == {:ip6, [?+, "2001::/32"], 0..12}
    end

    test "anything really" do
      # Note: ip6 cheats and lexes any non-spaces since ip6 parsing is done
      # later on by the Parser.
      {:ok, [token], _, _, _, _} = ip6("ip6:a.b.c.d/xy")
      assert token == {:ip6, [?+, "a.b.c.d/xy"], 0..13}
    end
  end

  describe "mx() lexes" do
    defparsec(:mx, Spf.Tokens.mx())

    test "mx default qualifier" do
      assert mx("mx") == {:ok, [{:mx, [?+, []], 0..1}], "", %{start: 0}, {1, 0}, 2}
    end

    test "mx with qualifier" do
      testcases = for q <- ["+", "-", "~", "?"], do: {charcode(q), "#{q}mx"}

      check = fn q, str ->
        assert mx(str) == {:ok, [{:mx, [q, []], 0..2}], "", %{start: 0}, {1, 0}, 3}
      end

      Enum.map(testcases, fn {l, str} -> check.(l, str) end)
    end

    test "mx with dual_cidr" do
      {:ok, [token], _, _, _, _} = mx("mx/24")
      assert token == {:mx, [?+, [{:dual_cidr, [24, 128], 2..4}]], 0..4}
    end

    test "mx with domain_spec" do
      {:ok, [token], _, _, _, _} = mx("mx:%{d}.com")

      assert token ==
               {:mx,
                [
                  ?+,
                  [
                    {:domain_spec,
                     [
                       {:expand, [?d, 0, false, ["."]], 3..6},
                       {:literal, ".com", 7..10}
                     ], 3..10}
                  ]
                ], 0..10}
    end

    test "mx with domain_spec and dual_cidr" do
      {:ok, [token], _, _, _, _} = mx("mx:%{d}.com/24//64")

      assert token ==
               {:mx,
                [
                  ?+,
                  [
                    {:domain_spec,
                     [
                       {:expand, [?d, 0, false, ["."]], 3..6},
                       {:literal, ".com", 7..10}
                     ], 3..10},
                    {:dual_cidr, [24, 64], 11..17}
                  ]
                ], 0..17}
    end
  end

  describe "ptr() lexes" do
    defparsec(:ptr, Spf.Tokens.ptr())

    test "all qualifiers" do
      assert ptr("ptr") == {:ok, [{:ptr, [?+, []], 0..2}], "", %{start: 0}, {1, 0}, 3}
      assert ptr("+ptr") == {:ok, [{:ptr, [?+, []], 0..3}], "", %{start: 0}, {1, 0}, 4}
      assert ptr("-ptr") == {:ok, [{:ptr, [?-, []], 0..3}], "", %{start: 0}, {1, 0}, 4}
      assert ptr("~ptr") == {:ok, [{:ptr, [?~, []], 0..3}], "", %{start: 0}, {1, 0}, 4}
      assert ptr("?ptr") == {:ok, [{:ptr, [??, []], 0..3}], "", %{start: 0}, {1, 0}, 4}
    end

    test "its domain_spec" do
      {:ok, [token], _, _, _, _} = ptr("ptr:spf.example.com")

      assert token ==
               {:ptr, [?+, [{:domain_spec, [{:literal, "spf.example.com", 4..18}], 4..18}]],
                0..18}
    end
  end

  describe "exp() lexes" do
    defparsec(:exp, Spf.Tokens.exp())

    test "its domain-spec" do
      {:ok, [token], _, _, _, _} = exp("exp=%{d}.com")

      assert token ==
               {:exp,
                [
                  {:domain_spec,
                   [
                     {:expand, [?d, 0, false, ["."]], 4..7},
                     {:literal, ".com", 8..11}
                   ], 4..11}
                ], 0..11}
    end
  end

  describe "explain() lexes" do
    defparsec(:explain, Spf.Tokens.exp_str())

    test "an explain-string" do
      {:ok, tokens, _, _, _, _} = explain("%{i} is bad")

      assert tokens ==
               [
                 {:exp_str,
                  [
                    {:domain_spec, [{:expand, [105, 0, false, ["."]], 0..3}], 0..3},
                    {:whitespace, [" "], 4..4},
                    {:domain_spec, [{:literal, "is", 5..6}], 5..6},
                    {:whitespace, [" "], 7..7},
                    {:domain_spec, [{:literal, "bad", 8..10}], 8..10}
                  ], 0..10}
               ]
    end
  end

  describe "redirect() lexes" do
    defparsec(:redirect, Spf.Tokens.redirect())

    test "its domain-spec" do
      {:ok, [token], _, _, _, _} = redirect("redirect=%{d}.com")

      assert token ==
               {:redirect,
                [
                  {:domain_spec,
                   [
                     {:expand, [?d, 0, false, ["."]], 9..12},
                     {:literal, ".com", 13..16}
                   ], 9..16}
                ], 0..16}
    end
  end

  describe "version() lexes" do
    defparsec(:version, Spf.Tokens.version())

    test "any number actually" do
      {:ok, [token], _, _, _, _} = version("v=spf1")
      assert token == {:version, [1], 0..5}

      {:ok, [token], _, _, _, _} = version("v=spf11")
      assert token == {:version, [11], 0..6}
    end

    test "case-insensitive" do
      {:ok, [token], _, _, _, _} = version("V=SpF11")
      assert token == {:version, [11], 0..6}
    end
  end

  describe "expand() lexes" do
    defparsec(:expand, Spf.Tokens.expand())

    test "specials" do
      {:ok, [token], _, _, _, _} = expand("%%")
      assert token == {:expand, '%', 0..1}

      {:ok, [token], _, _, _, _} = expand("%-")
      assert token == {:expand, '-', 0..1}

      {:ok, [token], _, _, _, _} = expand("%_")
      assert token == {:expand, '_', 0..1}
    end

    test "simple macros (both cases)" do
      check = fn l, str ->
        assert expand(str) ==
                 {:ok, [{:expand, [charcode(l), 0, false, ["."]], 0..3}], "", %{start2: 0},
                  {1, 0}, 4}
      end

      testcases = for l <- @mletters, do: {l, "%{#{l}}"}
      Enum.map(testcases, fn {l, str} -> check.(l, str) end)
    end
  end

  describe "literal() lexes" do
    defparsec(:literal, Spf.Tokens.literal())

    test "anything visible, except %" do
      {:ok, [token], rest, _, _, _} = literal("tillhere%see?")
      assert rest == "%see?"
      assert token == {:literal, "tillhere", 0..7}
    end

    test "anything visible, so stops at whitespace" do
      {:ok, [token], rest, _, _, _} = literal("tillhere see?")
      assert rest == " see?"
      assert token == {:literal, "tillhere", 0..7}

      {:ok, [token], rest, _, _, _} = literal("tillhere\tsee?")
      assert rest == "\tsee?"
      assert token == {:literal, "tillhere", 0..7}
    end
  end
end
