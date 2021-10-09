defmodule Spf.TokenTest do
  use ExUnit.Case
  import NimbleParsec

  # assertions
  # from https://elixirforum.com/t/trying-to-write-a-simple-nimble-parsec-parser/41344/4

  @mletters String.split("slodiphcrtvSLODIPHCRTV", "", trim: true)

  def charcode(charstr) when is_binary(charstr),
    do: String.to_charlist(charstr) |> List.first()

  describe "domspec() parses" do
    defparsecp(:domspec, Spf.Tokens.domspec(":"))

    test "simple macros" do
      check = fn l, str ->
        {:ok, [{:domspec, [{:expand, [mletter, 0, false, ["."]], 1..4}], 1..4}], "", _context,
         _linepos, 5} = domspec(str)

        assert charcode(l) == mletter, str
      end

      testcases = for l <- @mletters, do: {l, ":%{#{l}}"}
      Enum.map(testcases, fn {l, str} -> check.(l, str) end)
    end

    test "macros with keep" do
      check = fn l, str ->
        {:ok, [{:domspec, [{:expand, [mletter, 3, false, ["."]], 1..5}], 1..5}], "", _context,
         _linepos, 6} = domspec(str)

        assert mletter == charcode(l), str
      end

      testcases = for l <- @mletters, do: {l, ":%{#{l}3}"}
      Enum.map(testcases, fn {l, str} -> check.(l, str) end)
    end

    test "macros with reverse" do
      check = fn l, str ->
        {:ok, [{:domspec, [{:expand, [mletter, 0, true, ["."]], 1..5}], 1..5}], "", _context,
         _linepos, _} = domspec(str)

        assert charcode(l) == mletter, str
      end

      testcases = for l <- @mletters, do: {l, ":%{#{l}r}"}
      Enum.map(testcases, fn {l, str} -> check.(l, str) end)
      # also uppercase R
      testcases = for l <- @mletters, do: {l, ":%{#{l}R}"}
      Enum.map(testcases, fn {l, str} -> check.(l, str) end)
    end

    test "macros with keep and reverse" do
      check = fn l, str ->
        {:ok, [{:domspec, [{:expand, [mletter, 9, true, ["."]], 1..6}], 1..6}], "", _context,
         _linepos, 7} = domspec(str)

        assert charcode(l) == mletter, str
      end

      testcases = for l <- @mletters, do: {l, ":%{#{l}9r}"}
      Enum.map(testcases, fn {l, str} -> check.(l, str) end)
      # also uppercase R
      testcases = for l <- @mletters, do: {l, ":%{#{l}9R}"}
      Enum.map(testcases, fn {l, str} -> check.(l, str) end)
    end

    test "macros with delimiters" do
      check = fn l, str ->
        {:ok,
         [
           {:domspec,
            [
              {:expand, [mletter, 0, false, [".", "-", "+", ",", "/", "_", "="]], 1..11}
            ], 1..11}
         ], "", _context, _linepos, 12} = domspec(str)

        assert charcode(l) == mletter, str
      end

      testcases = for l <- @mletters, do: {l, ":%{#{l}.-+,/_=}"}
      Enum.map(testcases, fn {l, str} -> check.(l, str) end)
    end

    test "macro specials" do
      {:ok, [token], _, _, _, _} = domspec(":%%")
      assert token == {:domspec, [{:expand, ["%"], 1..2}], 1..2}

      {:ok, [token], _, _, _, _} = domspec(":%-")
      assert token == {:domspec, [{:expand, ["-"], 1..2}], 1..2}

      {:ok, [token], _, _, _, _} = domspec(":%_")
      assert token == {:domspec, [{:expand, ["_"], 1..2}], 1..2}
    end

    test "macros with reverse and delimiters" do
      check = fn l, str ->
        {:ok,
         [
           {:domspec,
            [
              {:expand, [mletter, 0, true, [".", "-", "+", ",", "/", "_", "="]], 1..12}
            ], 1..12}
         ], "", _context, _linepos, 13} = domspec(str)

        assert charcode(l) == mletter, str
      end

      testcases = for l <- @mletters, do: {l, ":%{#{l}r.-+,/_=}"}
      Enum.map(testcases, fn {l, str} -> check.(l, str) end)
      # also uppercase R
      testcases = for l <- @mletters, do: {l, ":%{#{l}R.-+,/_=}"}
      Enum.map(testcases, fn {l, str} -> check.(l, str) end)
    end

    test "macros with keep, reverse and delimiters" do
      check = fn l, str ->
        {:ok,
         [
           {:domspec,
            [
              {:expand, [mletter, 11, true, [".", "-", "+", ",", "/", "_", "="]], 1..14}
            ], 1..14}
         ], "", _context, _linepos, 15} = domspec(str)

        assert charcode(l) == mletter, str
      end

      testcases = for l <- @mletters, do: {l, ":%{#{l}11r.-+,/_=}"}
      Enum.map(testcases, fn {l, str} -> check.(l, str) end)
      # also uppercase R
      testcases = for l <- @mletters, do: {l, ":%{#{l}11R.-+,/_=}"}
      Enum.map(testcases, fn {l, str} -> check.(l, str) end)
    end

    test "macros with keep, reverse, delims, literals and specials" do
      assert {:ok, [token], rest, _, _, _} = domspec(":%{d2R.-}%-.com/24")
      assert rest == "/24"

      assert token ==
               {:domspec,
                [
                  {:expand, [?d, 2, true, [".", "-"]], 1..8},
                  {:expand, ["-"], 9..10},
                  {:toplabel, [".com"], 11..14}
                ], 1..14}
    end

    test "macros but not a following dual_cidr" do
      {:ok, [token], rest, _, _, _} = domspec(":%{d}.com/24")

      assert token ==
               {:domspec, [{:expand, [?d, 0, false, ["."]], 1..4}, {:toplabel, [".com"], 5..8}],
                1..8}

      assert rest == "/24"

      {:ok, [_token], rest, _, _, _} = domspec(":%{d}.com//128")
      assert rest == "//128"

      {:ok, [_token], rest, _, _, _} = domspec(":%{d}.com/32//128")
      assert rest == "/32//128"

      {:ok, [_token], rest, _, _, _} = domspec(":%{d}.c%-o%_m%%/32//128")
      assert rest == "/32//128"
    end

    test ":.com/24//64.net/24:%{o2r+}" do
      msg = ":.com/24//64.net/24:%{o2r+}"
      {:ok, [{:domspec, list, _range}], rest, _, _, _} = domspec(msg)
      assert rest == ""
      assert {:expand, _, _} = List.last(list)
    end

    test ":/33//129.abc-1" do
      msg = ":/33//129.abc-1"
      {:ok, [{:domspec, list, _range}], rest, _, _, _} = domspec(msg)
      assert rest == ""
      assert length(list) == 9, msg <> "~>  #{inspect(list)}"
      assert {:toplabel, [".abc-1"], _} = List.last(list)
    end

    test ":_spf.example.com" do
      msg = ":_spf.example.com"
      {:ok, [{:domspec, list, 1..16}], rest, _, _, _} = domspec(msg)
      # list is a series of literals for _spf.example + a toplabel for .com
      assert rest == ""
      assert length(list) == 13, msg <> "~>  #{inspect(list)}"
    end

    test "empty domspec" do
      msg = ":"
      {:error, _, rest, _, _, _} = domspec(msg)
      assert rest == ""
    end
  end

  describe "unknown_mod() lexes" do
    defparsec(:unknown_mod, Spf.Tokens.unknown_mod())

    test "holy.cow=an:expression" do
      term = "holy.cow=an:expression"
      {:ok, [token], rest, _, _, _} = unknown_mod(term)
      assert rest == ""
      assert elem(token, 0) == :unknown_mod
      [name | _subtokens] = elem(token, 1)
      assert name == "holy.cow"
      # subtokens can include {:literal, ["string"], range} or {:expand, [""}, range]
    end

    test "holy-cow=%{r}%%expression" do
      term = "holy-cow=%{r}%%expression"
      {:ok, [token], rest, _, _, _} = unknown_mod(term)
      assert rest == ""
      assert elem(token, 0) == :unknown_mod
      [name | _subtokens] = elem(token, 1)
      assert name == "holy-cow"
      # subtokens can include {:literal, ["string"], range} or {:expand, [""}, range]
    end

    test "holy_cow=expression%{r} rest" do
      term = "holy-cow=%{r}%%expression rest"
      {:ok, [token], rest, _, _, _} = unknown_mod(term)
      assert rest == " rest"
      assert elem(token, 0) == :unknown_mod
      [name | _subtokens] = elem(token, 1)
      assert name == "holy-cow"
      # subtokens can include {:literal, ["string"], range} or {:expand, [""}, range]
    end

    test "but not holy%cow=n/a" do
      term = "holy%cow=n/a"
      result = unknown_mod(term)
      assert elem(result, 0) == :error
    end

    test "but not holy/cow=n/a" do
      term = "holy/cow=n/a"
      result = unknown_mod(term)
      assert elem(result, 0) == :error
    end
  end

  describe "toplabel()" do
    defparsecp(:toplabel, Spf.Tokens.toplabel())

    test "lexes .com" do
      {:ok, [{:toplabel, [toplabel], _range}], rest, _, _, _} = toplabel(".com")
      assert rest == ""
      assert toplabel == ".com"
    end

    test "lexes .com." do
      {:ok, [{:toplabel, [toplabel], _range}], rest, _, _, _} = toplabel(".com.")
      assert rest == ""
      assert toplabel == ".com."
    end

    test "lexes .1-1." do
      {:ok, [{:toplabel, [toplabel], _range}], rest, _, _, _} = toplabel(".1-1.")
      assert rest == ""
      assert toplabel == ".1-1."
    end

    test "lexes .com./24" do
      {:ok, [{:toplabel, [toplabel], _range}], rest, _, _, _} = toplabel(".com./24")
      assert rest == "/24"
      assert toplabel == ".com."
    end

    test "does not match .com-" do
      {:error, _, _, _, _, _} = toplabel(".com-")
    end

    test "does not match -com." do
      result = toplabel(".-com")
      assert elem(result, 0) == :error
    end

    test "does not match .123" do
      result = toplabel(".123")
      assert elem(result, 0) == :error
    end
  end

  describe "dual_cidr() lexes" do
    defparsecp(:cidr, Spf.Tokens.dual_cidr())

    test "/24" do
      str = "/24"
      {:ok, [{token, [24, 128], 0..2}], "", _context, _linepos, 3} = cidr(str)
      assert token == :dual_cidr, str
    end

    test "//64" do
      str = "//64"
      {:ok, [{token, [32, 64], 0..3}], "", _context, _linepos, 4} = cidr(str)
      assert token == :dual_cidr, str
    end

    test "/24//64" do
      str = "/24//64"
      {:ok, [{token, [24, 64], 0..6}], "", _context, _linepos, 7} = cidr(str)
      assert token == :dual_cidr, str
    end

    test "/33//129" do
      # parser will validate prefix lengths, not the lexer
      str = "/33//129"
      {:ok, [{token, [33, 129], 0..7}], "", _context, _linepos, 8} = cidr(str)
      assert token == :dual_cidr, str
    end
  end

  describe "whitespace() lexes" do
    defparsecp(:wspace, Spf.Tokens.whitespace())

    test "1 space" do
      {:ok, [{:whitespace, [" "], 0..0}], "", _context, _linepos, 1} = wspace(" ")
    end

    test "1+ spaces" do
      {:ok, [{:whitespace, ["   "], 0..2}], "", _context, _linepos, 3} = wspace("   ")
    end

    test "1+ tabs" do
      {:ok, [{:whitespace, ["\t\t"], 0..1}], "", _context, _linepos, 2} = wspace("\t\t")
    end

    test "1+ (SP / TAB)" do
      {:ok, [{:whitespace, [" \t "], 0..2}], "", _context, _linepos, 3} = wspace(" \t ")
    end
  end

  describe "a() lexes" do
    defparsec(:a, Spf.Tokens.a())

    @str "a"
    test @str do
      {:ok, [token], _, _, _, _} = a(@str)
      {:a, [?+, []], 0..0} = token
    end

    @str "a:"
    test @str do
      {:error, _, _, _, _, _} = a(@str)
    end

    @str "a/24"
    test @str do
      {:ok, [token], _, _, _, _} = a(@str)
      {:a, [?+, [{:dual_cidr, [24, 128], 1..3}]], 0..3} = token
    end

    @str "a/24//64"
    test @str do
      {:ok, [token], _, _, _, _} = a(@str)
      {:a, [?+, [{:dual_cidr, [24, 64], 1..7}]], 0..7} = token
    end

    @str "a:/24//64"
    test @str do
      # empty domspec is illegal
      {:error, _, _, _, _, _} = a(@str)
    end

    @str "a:/24//64/0//0"
    test @str do
      # domspec not empty, but does not end with an expand or toplabel
      {:ok, [token], _, _, _, _} = a(@str)
      {:a, [43, [{:domspec, [:einvalid], 2..8}, {:dual_cidr, [0, 0], 9..13}]], 0..13} = token
    end

    @str "a:l1.l2.tld./24//64"
    test @str do
      {:ok, [token], _, _, _, _} = a(@str)
      {:a, [?+, [{:domspec, list, 2..11}, {:dual_cidr, [24, 64], 12..18}]], 0..18} = token
      {:toplabel, [".tld."], _} = List.last(list)
    end

    @str "a:l1.l2.tld.%{d}/24//64"
    test @str do
      {:ok, [token], _, _, _, _} = a(@str)
      {:a, [?+, [{:domspec, list, 2..15}, {:dual_cidr, [24, 64], 16..22}]], 0..22} = token
      {:expand, [?d, 0, false, ["."]], 12..15} = List.last(list)
    end

    test "a with default qualifier" do
      {:ok, [{:a, [?+, []], 0..0}], "", _context, _linepos, 1} = a("a")
    end

    test "a with cidr" do
      {:ok, [{:a, [?+, [{:dual_cidr, [24, 128], 1..3}]], 0..3}], "", _context, _linepos, 4} =
        a("a/24")
    end

    test "a with domspec" do
      str = "a:%{d}"

      {:ok,
       [
         {token, [43, [{:domspec, [{:expand, [100, 0, false, ["."]], 2..5}], 2..5}]], 0..5}
       ], "", _context, _linepos, 6} = a(str)

      assert token == :a, str
    end

    test "a with domspec and ipv4 cidr" do
      str = "a:%{d}/24"

      {:ok,
       [
         {token,
          [
            43,
            [
              {:domspec, [{:expand, [100, 0, false, ["."]], 2..5}], 2..5},
              {:dual_cidr, [24, 128], 6..8}
            ]
          ], 0..8}
       ], "", _context, _linepos, 9} = a(str)

      assert token == :a, str
    end

    test "a with domspec and ipv6 cidr" do
      str = "a:%{d}//64"

      {:ok,
       [
         {token,
          [
            43,
            [
              {:domspec, [{:expand, [100, 0, false, ["."]], 2..5}], 2..5},
              {:dual_cidr, [32, 64], 6..9}
            ]
          ], 0..9}
       ], "", _context, _linepos, 10} = a(str)

      assert token == :a, str
    end

    test "a with domspec and dual cidr" do
      str = "a:%{d}/24//64"

      {:ok,
       [
         {:a,
          [
            43,
            [
              {:domspec, [{:expand, [100, 0, false, ["."]], 2..5}], 2..5},
              {:dual_cidr, [24, 64], 6..12}
            ]
          ], 0..12}
       ], "", _context, _linepos, 13} = a(str)
    end

    test "a with qualifier, domspec and dual cidr" do
      testcases = for q <- ["+", "-", "~", "?"], do: {charcode(q), "#{q}a:%{d}/24//64"}

      check = fn q, str ->
        {:ok,
         [
           {token,
            [
              qual,
              [
                {:domspec, [{:expand, [100, 0, false, ["."]], 3..6}], 3..6},
                {:dual_cidr, [24, 64], 7..13}
              ]
            ], 0..13}
         ], "", _context, _linepos, 14} = a(str)

        assert token == :a, str
        assert qual == q, str
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
        {:ok, [{:all, [qual], 0..3}], "", _context, _linepos, 4} = all(str)
        assert qual == q, str
      end

      Enum.map(testcases, fn {l, str} -> check.(l, str) end)
    end

    test "all requires proper term ending" do
      result = all("all:")
      assert elem(result, 0) == :error
    end
  end

  describe "exists() lexes" do
    defparsec(:exists, Spf.Tokens.exists())

    test "its domspec" do
      {:ok, [token], _, _, _, _} = exists("exists:%{d1R-}.com")

      assert token ==
               {:exists,
                [
                  ?+,
                  {:domspec,
                   [
                     {:expand, [?d, 1, true, ["-"]], 7..13},
                     {:toplabel, [".com"], 14..17}
                   ], 7..17}
                ], 0..17}
    end

    # test "proper term ending" do
    #   result = exists("exists:")
    #   assert elem(result, 0) == :error

    #   result = exists("exists:example.com\24")
    #   assert elem(result, 0) == :error
    # end
  end

  describe "include() lexes" do
    defparsec(:include, Spf.Tokens.include())

    test "its domspec" do
      {:ok, [token], _, _, _, _} = include("include:spf.example.com")

      {:include, [?+, {:domspec, list, _}], _} = token
      assert length(list) == 12
      assert {:toplabel, [".com"], 19..22} == List.last(list)
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
      {:ok, [{:mx, [?+, []], 0..1}], "", _context, _linepos, 2} = mx("mx")
    end

    test "mx with qualifier" do
      testcases = for q <- ["+", "-", "~", "?"], do: {charcode(q), "#{q}mx"}

      check = fn q, str ->
        {:ok, [{:mx, [qual, []], 0..2}], "", _context, _linepos, 3} = mx(str)
        assert qual == q, str
      end

      Enum.map(testcases, fn {l, str} -> check.(l, str) end)
    end

    test "mx with dual_cidr" do
      {:ok, [token], _, _, _, _} = mx("mx/24")
      assert token == {:mx, [?+, [{:dual_cidr, [24, 128], 2..4}]], 0..4}
    end

    test "mx with domspec" do
      {:ok, [token], _, _, _, _} = mx("mx:%{d}.com")

      assert token ==
               {:mx,
                [
                  ?+,
                  [
                    {:domspec,
                     [
                       {:expand, [?d, 0, false, ["."]], 3..6},
                       {:toplabel, [".com"], 7..10}
                     ], 3..10}
                  ]
                ], 0..10}
    end

    test "mx with domspec and dual_cidr" do
      {:ok, [token], _, _, _, _} = mx("mx:%{d}.com/24//64")

      assert token ==
               {:mx,
                [
                  ?+,
                  [
                    {:domspec,
                     [
                       {:expand, [?d, 0, false, ["."]], 3..6},
                       {:toplabel, [".com"], 7..10}
                     ], 3..10},
                    {:dual_cidr, [24, 64], 11..17}
                  ]
                ], 0..17}
    end
  end

  describe "ptr() lexes" do
    defparsec(:ptr, Spf.Tokens.ptr())

    test "all qualifiers" do
      {:ok, [{:ptr, [?+, []], 0..2}], "", _context, _linepos, 3} = ptr("ptr")
      {:ok, [{:ptr, [?+, []], 0..3}], "", _context, _linepos, 4} = ptr("+ptr")
      {:ok, [{:ptr, [?-, []], 0..3}], "", _context, _linepos, 4} = ptr("-ptr")
      {:ok, [{:ptr, [?~, []], 0..3}], "", _context, _linepos, 4} = ptr("~ptr")
      {:ok, [{:ptr, [??, []], 0..3}], "", _context, _linepos, 4} = ptr("?ptr")
    end

    test "its domspec" do
      {:ok, [token], _, _, _, _} = ptr("ptr:spf.example.com")
      {:ptr, [?+, [{:domspec, _list, 4..18}]], 0..18} = token
    end
  end

  describe "exp() lexes" do
    defparsec(:exp, Spf.Tokens.exp())

    test "its domain-spec" do
      {:ok, [token], _, _, _, _} = exp("exp=%{d}.com")

      assert token ==
               {:exp,
                [
                  {:domspec,
                   [
                     {:expand, [?d, 0, false, ["."]], 4..7},
                     {:toplabel, [".com"], 8..11}
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
                    {:expand, [105, 0, false, ["."]], 0..3},
                    {:whitespace, [" "], 4..4},
                    {:literal, ["i"], 5..5},
                    {:literal, ["s"], 6..6},
                    {:whitespace, [" "], 7..7},
                    {:literal, ["b"], 8..8},
                    {:literal, ["a"], 9..9},
                    {:literal, ["d"], 10..10}
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
                  {:domspec,
                   [
                     {:expand, [?d, 0, false, ["."]], 9..12},
                     {:toplabel, [".com"], 13..16}
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
      assert token == {:expand, ["%"], 0..1}

      {:ok, [token], _, _, _, _} = expand("%-")
      assert token == {:expand, ["-"], 0..1}

      {:ok, [token], _, _, _, _} = expand("%_")
      assert token == {:expand, ["_"], 0..1}
    end

    test "simple macros (both cases)" do
      check = fn l, str ->
        {:ok, [{:expand, [mletter, 0, false, ["."]], 0..3}], "", _context, _linepos, 4} =
          expand(str)

        assert mletter == charcode(l), str
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
      assert token == {:literal, ["tillhere"], 0..7}
    end

    test "anything visible, so stops at whitespace" do
      {:ok, [token], rest, _, _, _} = literal("tillhere see?")
      assert rest == " see?"
      assert token == {:literal, ["tillhere"], 0..7}

      {:ok, [token], rest, _, _, _} = literal("tillhere\tsee?")
      assert rest == "\tsee?"
      assert token == {:literal, ["tillhere"], 0..7}
    end
  end

  describe "unknown() lexes" do
    defparsec(:unknown, Spf.Tokens.unknown())

    test "anything visible, including %" do
      {:ok, [token], rest, _, _, _} = unknown("pasthere%see?")
      assert rest == ""
      assert token == {:unknown, 'pasthere%see?', 0..12}
    end

    test "anything visible, so stops at whitespace" do
      {:ok, [token], rest, _, _, _} = unknown("tillhere see?")
      assert rest == " see?"
      assert token == {:unknown, 'tillhere', 0..7}

      {:ok, [token], rest, _, _, _} = unknown("tillhere\tsee?")
      assert rest == "\tsee?"
      assert token == {:unknown, 'tillhere', 0..7}
    end
  end
end
