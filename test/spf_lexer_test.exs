defmodule Spf.LexerTest do
  use ExUnit.Case
  doctest Spf.Lexer

  @mletters String.split("crtslodiphvCRTSLODIPHCRTV", "", trim: true)
  @null_slice 1..0//-1

  defp charcode(charstr) when is_binary(charstr),
    do: String.to_charlist(charstr) |> List.first()

  describe "spf edge cases" do
    @describetag :tokens_spf_edge
    test "01 - lexes literally everything" do
      spf = "The quick brown fox jumps over the lazy dog"
      {:ok, tokens, rest, ctx} = Spf.Lexer.tokenize_spf(spf)
      errors = Enum.filter(tokens, fn {type, _, _} -> type == :error end)
      assert 9 == length(errors)
      assert "" == rest
      assert "" == ctx.input
    end

    test "02 - lexes empty string" do
      spf = ""
      {:ok, tokens, rest, ctx} = Spf.Lexer.tokenize_spf(spf)
      assert 0 == length(tokens)
      assert "" == rest
      assert "" == ctx.input
    end
  end

  describe "macros" do
    @describetag :macros
    # macro is {:expand, [code, keep, reverse, delims], range}
    def check_macro(spf, code, keep, reverse, delims, range) do
      {:ok, tokens, "", _} = Spf.Lexer.tokenize_spf(spf)
      [{:a, [_q, expand, _cidr], _}] = tokens
      {:expand, [mcode, mkeep, mreverse, mdelims], mrange} = expand
      msg = "macros; testing #{spf} -> failed on "

      assert code == mcode, msg <> "code"
      assert keep == mkeep, msg <> "keep"
      assert reverse == mreverse, msg <> "reverse"
      assert delims == mdelims, msg <> "delims"
      assert range == mrange, msg <> "range"
    end

    test "01 - simple macros" do
      testcases = for l <- @mletters, do: {charcode(l), "a:%{#{l}}"}
      keep = -1
      reverse = false
      delims = ["."]
      range = 2..5

      Enum.map(testcases, fn {l, spf} -> check_macro(spf, l, keep, reverse, delims, range) end)
    end

    test "02 - macros with keep" do
      testcases = for l <- @mletters, do: {charcode(l), "a:%{#{l}3}"}
      keep = 3
      reverse = false
      delims = ["."]
      range = 2..6

      Enum.map(testcases, fn {l, spf} -> check_macro(spf, l, keep, reverse, delims, range) end)

      # keep = 0, is valid
      testcases = for l <- @mletters, do: {charcode(l), "a:%{#{l}0}"}
      keep = 0
      reverse = false
      delims = ["."]
      range = 2..6

      Enum.map(testcases, fn {l, spf} -> check_macro(spf, l, keep, reverse, delims, range) end)
    end

    test "03 - macros with reverse" do
      testcases = for l <- @mletters, r <- ["r", "R"], do: {charcode(l), "a:%{#{l}#{r}}"}
      keep = -1
      reverse = true
      delims = ["."]
      range = 2..6

      Enum.map(testcases, fn {l, spf} -> check_macro(spf, l, keep, reverse, delims, range) end)
    end

    test "04 - macros with keep & reverse" do
      testcases = for l <- @mletters, r <- ["r", "R"], do: {charcode(l), "a:%{#{l}9#{r}}"}
      keep = 9
      reverse = true
      delims = ["."]
      range = 2..7
      Enum.map(testcases, fn {l, spf} -> check_macro(spf, l, keep, reverse, delims, range) end)
    end

    test "05 - macros with delimiters" do
      testcases = for l <- @mletters, do: {charcode(l), "a:%{#{l}.-+,/_=}"}
      keep = -1
      reverse = false
      delims = [".", "-", "+", ",", "/", "_", "="]
      range = 2..12
      Enum.map(testcases, fn {l, spf} -> check_macro(spf, l, keep, reverse, delims, range) end)
    end

    test "06 - macro special letters" do
      spf = "a:%%"
      {:ok, [{:a, [_q, expand, _cidr], 0..3}], "", _} = Spf.Lexer.tokenize_spf(spf)
      msg = "testing #{spf}"
      assert {:expand, ["%"], 2..3} == expand, msg

      spf = "a:%-"
      {:ok, [{:a, [_q, expand, _cidr], 0..3}], "", _} = Spf.Lexer.tokenize_spf(spf)
      msg = "testing #{spf}"
      assert {:expand, ["-"], 2..3} = expand, msg

      spf = "a:%_"
      {:ok, [{:a, [_q, expand, _cidr], 0..3}], "", _} = Spf.Lexer.tokenize_spf(spf)
      msg = "testing #{spf}"
      assert {:expand, ["_"], 2..3} = expand, msg
    end

    test "07 - macros with reverse and delimiters" do
      testcases = for l <- @mletters, r <- ["r", "R"], do: {charcode(l), "a:%{#{l}#{r}.-+,/_=}"}
      keep = -1
      reverse = true
      delims = [".", "-", "+", ",", "/", "_", "="]
      range = 2..13
      Enum.map(testcases, fn {l, spf} -> check_macro(spf, l, keep, reverse, delims, range) end)
    end

    test "08 - macros with keep, reverse and delimiters" do
      testcases = for l <- @mletters, r <- ["r", "R"], do: {charcode(l), "a:%{#{l}9#{r}.-+,/_=}"}
      keep = 9
      reverse = true
      delims = [".", "-", "+", ",", "/", "_", "="]
      range = 2..14

      Enum.map(testcases, fn {l, spf} -> check_macro(spf, l, keep, reverse, delims, range) end)
    end

    test "09 - macros with keep, reverse, delimiters, literals and specials" do
      spf = "a:%{d2r.-}%-.com"

      {:ok, [{:a, [_q, tok0, tok1, tok2, _cidr], 0..15}], "", _} = Spf.Lexer.tokenize_spf(spf)

      msg = "testing #{spf} -> fail on "

      assert {:expand, [?d, 2, true, [".", "-"]], 2..9} == tok0, msg <> inspect(tok0)
      assert {:expand, ["-"], 10..11} == tok1, msg <> inspect(tok1)
      assert {:literal, [".com"], 12..15} == tok2, msg <> inspect(tok2)
    end

    test "10 - macros followed by dual cidr" do
      spf = "a:%{d}/24"

      {:ok, [{:a, [?+, tok0, tok1], 0..8}], "", _} = Spf.Lexer.tokenize_spf(spf)
      msg = "testing #{spf} -> fail on "
      assert {:expand, [?d, -1, false, ["."]], 2..5} == tok0, msg <> inspect(tok0)
      assert {:cidr, [24, 128], 6..8} == tok1, msg <> inspect(tok1)
    end

    test "11 - macros followed by cidr" do
      spf = "a:%{d}//64"
      {:ok, [{:a, [?+, tok0, tok1], 0..9}], "", _} = Spf.Lexer.tokenize_spf(spf)

      msg = "testing #{spf} -> fail on "
      assert {:expand, [?d, -1, false, ["."]], 2..5} == tok0, msg <> inspect(tok0)
      assert {:cidr, [32, 64], 6..9} == tok1, msg <> inspect(tok1)
    end

    test "12 - macros followed by cidr" do
      spf = "a:%{d}/24//64"
      {:ok, [{:a, [?+, tok0, tok1], 0..12}], "", _} = Spf.Lexer.tokenize_spf(spf)

      msg = "testing #{spf} -> fail on "
      assert {:expand, [?d, -1, false, ["."]], 2..5} == tok0, msg <> inspect(tok0)
      assert {:cidr, [24, 64], 6..12} == tok1, msg <> inspect(tok1)
    end

    test "13 - macros followed by cidr" do
      spf = "a:%{d}.com/24"
      {:ok, [{:a, [?+, tok0, tok1, tok2], 0..12}], "", _} = Spf.Lexer.tokenize_spf(spf)

      msg = "testing #{spf} -> fail on "
      assert {:expand, [?d, -1, false, ["."]], 2..5} == tok0, msg <> inspect(tok0)
      assert {:literal, [".com"], 6..9} == tok1, msg <> inspect(tok1)
      assert {:cidr, [24, 128], 10..12} == tok2, msg <> inspect(tok2)

      # some variations
      spf = "a:%{d}.com/0//0"
      {:ok, [{:a, [?+, tok0, tok1, tok2], 0..14}], "", _} = Spf.Lexer.tokenize_spf(spf)
      msg = "testing #{spf} -> fail on "
      assert {:expand, [?d, -1, false, ["."]], 2..5} == tok0, msg <> inspect(tok0)
      assert {:literal, [".com"], 6..9} == tok1, msg <> inspect(tok1)
      assert {:cidr, [0, 0], 10..14} == tok2, msg <> inspect(tok2)

      spf = "a:%{d2r-.}.example.com/0//0"
      {:ok, [{:a, [?+, tok0, tok1, tok2], 0..26}], "", _} = Spf.Lexer.tokenize_spf(spf)
      msg = "testing #{spf} -> fail on "
      assert {:expand, [?d, 2, true, ["-", "."]], 2..9} == tok0, msg <> inspect(tok0)
      assert {:literal, [".example.com"], 10..21} == tok1, msg <> inspect(tok1)
      assert {:cidr, [0, 0], 22..26} == tok2, msg <> inspect(tok2)
    end

    test "14 - macros that end in expand" do
      spf = "a:%{d2r.-}.example.com/0//0.%{d}"
      {:ok, [{:a, [?+, tok0, tok1, tok2, tok3], 0..31}], "", _} = Spf.Lexer.tokenize_spf(spf)
      msg = "testing #{spf} -> fail on "
      assert {:expand, [?d, 2, true, [".", "-"]], 2..9} == tok0, msg <> inspect(tok0)
      assert {:literal, [".example.com/0//0."], 10..27} == tok1, msg <> inspect(tok1)
      assert {:expand, [?d, -1, false, ["."]], 28..31} == tok2, msg <> inspect(tok2)
      assert {:cidr, [32, 128], @null_slice} == tok3, msg <> inspect(tok3)
    end

    test "15 - macros that end in toplabel" do
      spf = "a:%{d2r-.}.example.com"
      {:ok, [{:a, [?+, tok0, tok1, tok2], 0..21}], "", _} = Spf.Lexer.tokenize_spf(spf)
      msg = "testing #{spf} -> fail on "
      assert {:expand, [?d, 2, true, ["-", "."]], 2..9} == tok0, msg <> inspect(tok0)
      assert {:literal, [".example.com"], 10..21} == tok1, msg <> inspect(tok1)
      assert {:cidr, [32, 128], @null_slice} == tok2, msg <> inspect(tok2)

      # lexer keeps trailing dot, parser will need to deal with it
      spf = "a:%{d2r-.}.example.com."
      {:ok, [{:a, [?+, tok0, tok1, tok2], 0..22}], "", _} = Spf.Lexer.tokenize_spf(spf)
      msg = "testing #{spf} -> fail on "
      assert {:expand, [?d, 2, true, ["-", "."]], 2..9} == tok0, msg <> inspect(tok0)
      assert {:literal, [".example.com."], 10..22} == tok1, msg <> inspect(tok1)
      assert {:cidr, [32, 128], @null_slice} == tok2, msg <> inspect(tok2)
    end

    test "16 - macros cannot be empty" do
      # invalid empty domspec
      spf = "a:"
      {:ok, [token], "", _} = Spf.Lexer.tokenize_spf(spf)
      {:error, ["a:"], 0..1} = token
    end
  end

  describe "unknown modifiers" do
    @describetag :tokens_unknown_modifier

    test "01 - holy.cow=an:expression" do
      term = "holy.cow=an:expression"
      msg = "testing #{term} -> fail on "
      {:ok, [{:unknown, ["holy.cow", tok0], 0..21}], "", _} = Spf.Lexer.tokenize_spf(term)
      assert {:literal, ["an:expression"], 9..21} == tok0, msg <> inspect(tok0)
    end

    test "02 - holy-cow=%{r}%%expression" do
      term = "holy-cow=%{r}%%expression"

      {:ok, [{:unknown, ["holy-cow", tok0, tok1, tok2], 0..24}], "", _} =
        Spf.Lexer.tokenize_spf(term)

      msg = "testing #{term} -> fail on "
      assert {:expand, [?r, -1, false, ["."]], 9..12} == tok0, msg <> inspect(tok0)
      assert {:expand, ["%"], 13..14} == tok1, msg <> inspect(tok1)
      assert {:literal, ["expression"], 15..24} == tok2, msg <> inspect(tok2)
    end

    test "03 - holy-cow=expression%{r} rest" do
      term = "holy-cow=%{r}%%expression rest"

      {:ok, [unknown, _whitespace, error], "", _} = Spf.Lexer.tokenize_spf(term)
      msg = "testing #{term} -> fail on "
      {:unknown, ["holy-cow", tok0, tok1, tok2], 0..24} = unknown
      assert {:expand, [?r, -1, false, ["."]], 9..12} == tok0, msg <> inspect(tok0)
      assert {:expand, ["%"], 13..14} == tok1, msg <> inspect(tok1)
      assert {:literal, ["expression"], 15..24} == tok2, msg <> inspect(tok2)
      assert {:error, ["rest"], 26..29} == error, msg <> inspect(error)
    end

    test "04 - error on holy%cow=n/a" do
      term = "holy%cow=n/a"
      {:ok, [{:error, ["holy%cow=n/a"], 0..11}], "", _} = Spf.Lexer.tokenize_spf(term)
    end

    test "05 - error on holy/cow=n/a" do
      term = "holy/cow=n/a"
      {:ok, [{:error, ["holy/cow=n/a"], _}], "", _} = Spf.Lexer.tokenize_spf(term)
    end

    test "06 - trailing dot is not dropped" do
      term = "unknown=example.com."
      {:ok, [{:unknown, ["unknown", literal], 0..19}], "", _} = Spf.Lexer.tokenize_spf(term)
      assert {:literal, ["example.com."], 8..19} == literal
    end

    test "07 - error in macro-string" do
      term = "unknown=example.%{z}.com"

      {:ok, [{:unknown, ["unknown", tok0, tok1, tok2], 0..23}], "", _} =
        Spf.Lexer.tokenize_spf(term)

      msg = "testing #{term} -> fail on "

      assert {:literal, ["example."], 8..15} == tok0, msg <> inspect(tok0)
      assert {:error, ["%"], 16..16} == tok1, msg <> inspect(tok1)
      assert {:literal, ["{z}.com"], 17..23} == tok2, msg <> inspect(tok2)
    end

    test "08 - error in macro-string" do
      term = "unknown=example.%{i}.c%m"

      {:ok, [{:unknown, ["unknown", tok0, tok1, tok2, tok3, tok4], 0..23}], "", _} =
        Spf.Lexer.tokenize_spf(term)

      msg = "testing #{term} -> fail on "

      assert {:literal, ["example."], 8..15} == tok0, msg <> inspect(tok0)
      assert {:expand, [?i, -1, false, ["."]], 16..19} == tok1, msg <> inspect(tok1)
      assert {:literal, [".c"], 20..21} == tok2, msg <> inspect(tok2)
      assert {:error, ["%"], 22..22} == tok3, msg <> inspect(tok3)
      assert {:literal, ["m"], 23..23} == tok4, msg <> inspect(tok4)
    end

    test "09 - error in macro-string, at the very beginning" do
      term = "unknown=%xample.%{d1r}"

      {:ok, [{:unknown, ["unknown", tok0, tok1, tok2], 0..21}], "", _} =
        Spf.Lexer.tokenize_spf(term)

      msg = "testing #{term} -> fail on "
      assert {:error, ["%"], 8..8} == tok0, msg <> inspect(tok0)
      assert {:literal, ["xample."], 9..15} == tok1, msg <> inspect(tok1)
      assert {:expand, [?d, 1, true, ["."]], 16..21} == tok2, msg <> inspect(tok2)
    end

    test "10 - error in macro-string, at the very end" do
      term = "unknown=example.%{i}.cm%"

      {:ok, [{:unknown, ["unknown", tok0, tok1, tok2, tok3], 0..23}], "", _} =
        Spf.Lexer.tokenize_spf(term)

      msg = "testing #{term} -> fail on "
      assert {:literal, ["example."], 8..15} == tok0, msg <> inspect(tok0)
      assert {:expand, [?i, -1, false, ["."]], 16..19} == tok1, msg <> inspect(tok1)
      assert {:literal, [".cm"], 20..22} == tok2, msg <> inspect(tok2)
      assert {:error, ["%"], 23..23} == tok3, msg <> inspect(tok3)
    end
  end

  describe "toplabels" do
    @describetag :tokens_toplabel
    # see also the macro tests
    test "01 - lexes .com" do
      {:ok, [{:a, [?+, tok0, tok1], 0..5}], "", _} = Spf.Lexer.tokenize_spf("a:.com")
      assert {:literal, [".com"], 2..5} == tok0
      assert {:cidr, [32, 128], @null_slice} == tok1
    end

    test "02 - lexes .com." do
      # lexer does not drop trailing dot
      {:ok, [{:a, [?+, tok0, tok1], 0..6}], "", _} = Spf.Lexer.tokenize_spf("a:.com.")
      assert {:literal, [".com."], 2..6} == tok0
      assert {:cidr, [32, 128], @null_slice} == tok1
    end

    test "03 - lexes .1-1." do
      {:ok, [{:a, [?+, tok0, tok1], 0..6}], "", _} = Spf.Lexer.tokenize_spf("a:.1-1.")
      assert {:literal, [".1-1."], 2..6} == tok0
      assert {:cidr, [32, 128], @null_slice} == tok1
    end

    test "04 - errors on .com-" do
      # parser will need to check validity of domain specification
      {:ok, [{:a, [?+, tok0, tok1], 0..6}], "", _} = Spf.Lexer.tokenize_spf("a:.com-")
      assert {:literal, [".com-"], 2..6} == tok0
      assert {:cidr, [32, 128], @null_slice} == tok1
    end

    test "05 - errors on  -com." do
      # parser will need to check validity of domain specification
      {:ok, [{:a, [?+, tok0, tok1], 0..6}], "", _} = Spf.Lexer.tokenize_spf("a:.-com")
      assert {:literal, [".-com"], 2..6} == tok0
      assert {:cidr, [32, 128], @null_slice} == tok1
    end

    test "06 - errors on .1234" do
      # parser will need to check validity of domain specification
      {:ok, [{:a, [?+, tok0, tok1], 0..6}], "", _} = Spf.Lexer.tokenize_spf("a:.1234")
      assert {:literal, [".1234"], 2..6} == tok0
      assert {:cidr, [32, 128], @null_slice} == tok1
    end
  end

  describe "cidr" do
    @describetag :tokens_cidr

    test "01 - /0//0" do
      {:ok, [{:a, [?+, cidr], _}], "", _} = Spf.Lexer.tokenize_spf("a/0//0")
      assert {:cidr, [0, 0], 1..5} == cidr
    end

    test "02 - /32//128" do
      {:ok, [{:a, [?+, cidr], _}], "", _} = Spf.Lexer.tokenize_spf("a/32//128")
      assert {:cidr, [32, 128], 1..8} == cidr
    end

    test "03 - /24" do
      {:ok, [{:a, [?+, cidr], _}], "", _} = Spf.Lexer.tokenize_spf("a/24")
      assert {:cidr, [24, 128], 1..3} == cidr
    end

    test "04 - //64" do
      {:ok, [{:a, [?+, cidr], _}], "", _} = Spf.Lexer.tokenize_spf("a//64")
      assert {:cidr, [32, 64], 1..4} == cidr
    end

    test "05 - /24//64" do
      {:ok, [{:a, [?+, cidr], _}], "", _} = Spf.Lexer.tokenize_spf("a/24//64")
      assert {:cidr, [24, 64], 1..7} == cidr
    end

    test "06 - /33//129" do
      # lexer lexes, parser will validate
      {:ok, [{:a, [?+, cidr], _}], "", _} = Spf.Lexer.tokenize_spf("a/33//129")
      assert {:cidr, [33, 129], 1..8} == cidr
    end

    test "07 - /08//128" do
      # lexer does not check for leading zero's in ip4-length
      {:ok, [{:a, [?+, cidr], _}], "", _} = Spf.Lexer.tokenize_spf("a/08//128")
      assert {:cidr, [8, 128], 1..8} == cidr
    end

    test "08 - 24//0128" do
      # lexer does not check for leading zero's in ip6-length
      {:ok, [{:a, [?+, cidr], _}], "", _} = Spf.Lexer.tokenize_spf("a/24//0128")
      assert {:cidr, [24, 128], 1..9} == cidr
    end

    test "09 - a-mech with cidr default" do
      {:ok, [{:a, [?+, cidr], _}], "", _} = Spf.Lexer.tokenize_spf("a")
      assert {:cidr, [32, 128], @null_slice} == cidr
    end

    test "10 - mx-mech with cidr default" do
      {:ok, [{:mx, [?+, cidr], _}], "", _} = Spf.Lexer.tokenize_spf("mx")
      assert {:cidr, [32, 128], @null_slice} == cidr
    end

    test "11 - ptr-mech has no cidr default" do
      {:ok, [{:ptr, [?+], 0..2}], "", _} = Spf.Lexer.tokenize_spf("ptr")
    end
  end

  describe "whitespace" do
    @describetag :tokens_whitespace

    test "01 - 1 space" do
      {:ok, [{:whitespace, [" "], 0..0}], "", _context} = Spf.Lexer.tokenize_spf(" ")
    end

    test "02 - 1+ spaces" do
      {:ok, [{:whitespace, ["   "], 0..2}], "", _context} = Spf.Lexer.tokenize_spf("   ")
    end

    test "03 - 1+ tabs" do
      {:ok, [{:whitespace, ["\t\t"], 0..1}], "", _context} = Spf.Lexer.tokenize_spf("\t\t")
    end

    test "04 - 1+ (SP / TAB)" do
      {:ok, [{:whitespace, [" \t "], 0..2}], "", _context} = Spf.Lexer.tokenize_spf(" \t ")
    end
  end

  describe "a-mechanism" do
    @describetag :tokens_a

    test "01 - a" do
      {:ok, [token], "", _} = Spf.Lexer.tokenize_spf("a")
      {:a, [?+, {:cidr, [32, 128], @null_slice}], 0..0} = token
    end

    test "02 - a:" do
      {:ok, [{:error, ["a:"], 0..1}], "", _} = Spf.Lexer.tokenize_spf("a:")
    end

    test "03 - a/24" do
      {:ok, [token], "", _} = Spf.Lexer.tokenize_spf("a/24")
      {:a, [?+, {:cidr, [24, 128], 1..3}], 0..3} = token
    end

    test "04 - a/24//64" do
      {:ok, [token], "", _} = Spf.Lexer.tokenize_spf("a/24//64")
      {:a, [?+, {:cidr, [24, 64], 1..7}], 0..7} = token
    end

    test "05 - a:/24//64" do
      # empty domain specification, parser checks validity
      {:ok, [token], "", _} = Spf.Lexer.tokenize_spf("a:/24//64")
      {:a, [?+, {:cidr, [24, 64], 2..8}], 0..8} = token
    end

    test "06 - a:/24//64/0//0" do
      # domspec not empty, but does not end with an expand or toplabel
      {:ok, [token], "", _} = Spf.Lexer.tokenize_spf("a:/24//64/0//0")
      {:a, [43, {:literal, ["/24//64"], 2..8}, {:cidr, [0, 0], 9..13}], 0..13} = token
    end

    test "07 - a:l1.l2.tld./24//64" do
      # note: trailing dot is not dropped from toplabel
      {:ok, [token], "", _} = Spf.Lexer.tokenize_spf("a:l1.l2.tld./24//64")
      {:a, [?+, {:literal, ["l1.l2.tld."], 2..11}, {:cidr, [24, 64], 12..18}], 0..18} = token
    end

    test "08 - a:l1.l2.tld.%{d}/24//64" do
      # note: tok2 is null literal ?
      term = "a:l1.l2.tld.%{d}/24//64"
      {:ok, [{:a, [?+, tok0, tok1, tok2], 0..22}], "", _} = Spf.Lexer.tokenize_spf(term)
      msg = "testing #{term}, fail on "
      assert {:literal, ["l1.l2.tld."], 2..11} == tok0, msg <> inspect(tok0)
      assert {:expand, [?d, -1, false, ["."]], 12..15} == tok1, msg <> inspect(tok1)
      assert {:cidr, [24, 64], 16..22} == tok2, msg <> inspect(tok2)
    end

    test "09 - a with explicit qualifier" do
      {:ok, [{:a, [?+, _cidr], 0..0}], "", _ctx} = Spf.Lexer.tokenize_spf("a")
      {:ok, [{:a, [?+, _cidr], 0..1}], "", _ctx} = Spf.Lexer.tokenize_spf("+a")
      {:ok, [{:a, [?-, _cidr], 0..1}], "", _ctx} = Spf.Lexer.tokenize_spf("-a")
      {:ok, [{:a, [?~, _cidr], 0..1}], "", _ctx} = Spf.Lexer.tokenize_spf("~a")
      {:ok, [{:a, [??, _cidr], 0..1}], "", _ctx} = Spf.Lexer.tokenize_spf("?a")
    end

    test "10 - a with domspec error" do
      {:ok, [{:a, [?+, tok1, tok2, tok3], _}], "", _} = Spf.Lexer.tokenize_spf("a:%.com")
      assert tok1 == {:error, ["%"], 2..2}
      assert tok2 == {:literal, [".com"], 3..6}
      assert tok3 == {:cidr, [32, 128], @null_slice}
    end
  end

  describe "all-mechanism" do
    @describetag :tokens_all

    test "01 - implicit  qualifier" do
      {:ok, [token], "", _} = Spf.Lexer.tokenize_spf("all")
      assert {:all, [?+], 0..2} == token
    end

    test "02 - explicit qualifier" do
      {:ok, [{:all, [?+], 0..3}], "", _} = Spf.Lexer.tokenize_spf("+all")
      {:ok, [{:all, [?-], 0..3}], "", _} = Spf.Lexer.tokenize_spf("-all")
      {:ok, [{:all, [?~], 0..3}], "", _} = Spf.Lexer.tokenize_spf("~all")
      {:ok, [{:all, [??], 0..3}], "", _} = Spf.Lexer.tokenize_spf("?all")
    end

    test "03 - requires eot after all" do
      result = Spf.Lexer.tokenize_spf("all:")
      {:ok, [{:error, ["all:"], 0..3}], "", _} = result
    end

    test "04 - requires eot after all" do
      # an empty macro-string is actually valid for unknown modifier
      # https://www.rfc-editor.org/rfc/rfc7208.html#section-12
      # - unknown-modifier = name "=" macro-string
      # - macro-string     = *( macro-expand / macro-literal )
      {:ok, [{:unknown, ["all"], 0..3}], "", _} = Spf.Lexer.tokenize_spf("all=")
    end

    test "05 - requires eot after all" do
      result = Spf.Lexer.tokenize_spf("all.")
      {:ok, [{:error, ["all."], _}], "", _} = result
    end

    test "06 - requires eot after all" do
      result = Spf.Lexer.tokenize_spf("all:isnotwell")
      {:ok, [{:error, ["all:isnotwell"], _}], "", _} = result
    end
  end

  describe "exists-mechanism" do
    @describetag :tokens_exists
    test "01 - domspec" do
      {:ok, [{:exists, [?+, expand, literal], 0..17}], "", _} =
        Spf.Lexer.tokenize_spf("exists:%{d1R-}.com")

      assert {:expand, [?d, 1, true, ["-"]], 7..13} == expand
      assert {:literal, [".com"], 14..17} == literal
    end

    test "02 - errors on empty domspec" do
      {:ok, [{:error, ["exists:"], 0..6}], "", _} = Spf.Lexer.tokenize_spf("exists:")
    end

    test "03 - requires : separator" do
      # parser will check if name is a mechanism name and warn accordingly
      # because technically, it is not an error.
      {:ok, [{:unknown, ["exists", literal], 0..11}], "", _} =
        Spf.Lexer.tokenize_spf("exists=a.com")

      assert {:literal, ["a.com"], 7..11} == literal
    end
  end

  describe "include-mechanism" do
    @describetag :tokens_include
    test "01 - domspec" do
      {:ok, [{:include, [?+, literal], 0..22}], "", _} =
        Spf.Lexer.tokenize_spf("include:spf.example.com")

      assert {:literal, ["spf.example.com"], 8..22} == literal
    end

    test "02 - domspec, trailing dot not dropped" do
      {:ok, [{:include, [?+, literal], 0..23}], "", _} =
        Spf.Lexer.tokenize_spf("include:spf.example.com.")

      assert {:literal, ["spf.example.com."], 8..23} == literal
    end

    test "03 - errors on empty domspec" do
      {:ok, [{:error, ["include:"], 0..7}], "", _} = Spf.Lexer.tokenize_spf("include:")
    end

    test "04 - requires : separator" do
      {:ok, [{:unknown, ["include", literal], 0..12}], "", _} =
        Spf.Lexer.tokenize_spf("include=a.com")

      assert {:literal, ["a.com"], 8..12} == literal
    end
  end

  describe "ip4-mechanism" do
    @describetag :tokens_ip4

    test "01 - lexes an address" do
      {:ok, [{:ip4, [?+, literal], 0..10}], "", _} = Spf.Lexer.tokenize_spf("ip4:1.2.3.4")
      assert {:literal, ["1.2.3.4"], 4..10} == literal
    end

    test "02 - lexes a prefix" do
      {:ok, [{:ip4, [?+, literal], 0..13}], "", _} = Spf.Lexer.tokenize_spf("ip4:1.2.3.4/32")
      assert {:literal, ["1.2.3.4/32"], 4..13} == literal
    end

    test "03 - lexes anything really" do
      # note: validity of ip address is checked by the parser
      {:ok, [{:ip4, [?+, literal], 0..13}], "", _} = Spf.Lexer.tokenize_spf("ip4:a.b.c.d/xy")
      assert {:literal, ["a.b.c.d/xy"], 4..13} == literal
    end

    test "04 - requires : separator" do
      {:ok, [{:unknown, ["ip4", literal], 0..10}], "", _} = Spf.Lexer.tokenize_spf("ip4=1.1.1.1")
      assert {:literal, ["1.1.1.1"], 4..10} == literal
    end

    test "05 - requires : separator" do
      {:ok, [token], "", _} = Spf.Lexer.tokenize_spf("ip4")
      assert {:error, ["ip4"], 0..2} == token
    end

    test "06 - requires something after :" do
      {:ok, [token], "", _} = Spf.Lexer.tokenize_spf("ip4:")
      assert {:error, ["ip4:"], 0..3} == token
    end
  end

  describe "ip6-mechanism" do
    @describetag :tokens_ip6

    test "01 - lexes an address" do
      {:ok, [{:ip6, [?+, literal], 0..10}], "", _} = Spf.Lexer.tokenize_spf("ip6:2001::4")
      assert {:literal, ["2001::4"], 4..10} == literal
    end

    test "02 - lexes a prefix" do
      {:ok, [{:ip6, [?+, literal], 0..12}], "", _} = Spf.Lexer.tokenize_spf("ip6:2001::/32")
      assert {:literal, ["2001::/32"], 4..12} == literal
    end

    test "03 - lexes anything really" do
      # note: validity of ip6 address/prefix is checked by the parser
      {:ok, [{:ip6, [?+, literal], 0..20}], "", _} =
        Spf.Lexer.tokenize_spf("ip6:::ffff:1.1.1.1/xy")

      assert {:literal, ["::ffff:1.1.1.1/xy"], 4..20} == literal
    end

    test "04 - requires : separator" do
      {:ok, [{:unknown, ["ip6", literal], 0..13}], "", _} =
        Spf.Lexer.tokenize_spf("ip6=2001:db8::")

      assert {:literal, ["2001:db8::"], 4..13} == literal
    end

    test "05 - requires : separator" do
      {:ok, [token], "", _} = Spf.Lexer.tokenize_spf("ip6")
      assert {:error, ["ip6"], 0..2} == token
    end

    test "06 - requires something after :" do
      {:ok, [token], "", _} = Spf.Lexer.tokenize_spf("ip6:")
      assert {:error, ["ip6:"], 0..3} == token
    end
  end

  describe "mx-mechanism" do
    @describetag :tokens_mx

    test "01 - default qualifier" do
      {:ok, [{:mx, [?+, cidr], 0..1}], "", _} = Spf.Lexer.tokenize_spf("mx")
      assert {:cidr, [32, 128], @null_slice} == cidr
    end

    test "02 - explicit qualifier" do
      {:ok, [{:mx, [?+, _cidr], 0..2}], "", _} = Spf.Lexer.tokenize_spf("+mx")
      {:ok, [{:mx, [?-, _cidr], 0..2}], "", _} = Spf.Lexer.tokenize_spf("-mx")
      {:ok, [{:mx, [?~, _cidr], 0..2}], "", _} = Spf.Lexer.tokenize_spf("~mx")
      {:ok, [{:mx, [??, _cidr], 0..2}], "", _} = Spf.Lexer.tokenize_spf("?mx")
    end

    test "03 - with ip4 cidr" do
      {:ok, [{:mx, [?+, cidr], 0..4}], "", _} = Spf.Lexer.tokenize_spf("mx/24")
      assert {:cidr, [24, 128], 2..4} == cidr
    end

    test "04 - with ip6 cidr" do
      {:ok, [{:mx, [?+, cidr], 0..5}], "", _} = Spf.Lexer.tokenize_spf("mx//24")
      assert {:cidr, [32, 24], 2..5} == cidr
    end

    test "05 - with ip4 and ip6 cidr" do
      {:ok, [{:mx, [?+, cidr], 0..8}], "", _} = Spf.Lexer.tokenize_spf("mx/16//24")
      assert {:cidr, [16, 24], 2..8} == cidr
    end

    test "06 - with domspec" do
      {:ok, [{:mx, [?+, expand, literal, cidr], 0..10}], "", _} =
        Spf.Lexer.tokenize_spf("mx:%{d}.com")

      assert {:expand, [?d, -1, false, ["."]], 3..6} == expand
      assert {:literal, [".com"], 7..10} == literal
      assert {:cidr, [32, 128], @null_slice} == cidr
    end

    test "07 - with domspec and dual_cidr" do
      {:ok, [{:mx, [?+, expand, literal, cidr], 0..17}], "", _} =
        Spf.Lexer.tokenize_spf("mx:%{d}.com/24//64")

      assert {:expand, [?d, -1, false, ["."]], 3..6} == expand
      assert {:literal, [".com"], 7..10} == literal
      assert {:cidr, [24, 64], 11..17} == cidr
    end
  end

  describe "ptr-mechanism" do
    @describetag :tokens_ptr

    test "01 - default qualifiers" do
      {:ok, [{:ptr, [?+], 0..2}], "", _} = Spf.Lexer.tokenize_spf("ptr")
    end

    test "02 - explicit qualifier" do
      {:ok, [{:ptr, [?+], 0..3}], "", _} = Spf.Lexer.tokenize_spf("+ptr")
      {:ok, [{:ptr, [?-], 0..3}], "", _} = Spf.Lexer.tokenize_spf("-ptr")
      {:ok, [{:ptr, [?~], 0..3}], "", _} = Spf.Lexer.tokenize_spf("~ptr")
      {:ok, [{:ptr, [??], 0..3}], "", _} = Spf.Lexer.tokenize_spf("?ptr")
    end

    test "03 - with domain specification" do
      {:ok, [{:ptr, [?+, literal], 0..18}], "", _} = Spf.Lexer.tokenize_spf("ptr:spf.example.com")
      assert {:literal, ["spf.example.com"], 4..18} == literal
    end

    test "04 - any cidr is not parsed, but taken literally" do
      {:ok, [{:ptr, [?+, literal], 0..21}], "", _} =
        Spf.Lexer.tokenize_spf("ptr:spf.example.com/24")

      assert {:literal, ["spf.example.com/24"], 4..21} == literal
    end
  end

  describe "exp-modifier" do
    @describetag :tokens_exp

    test "01 - domain-spec" do
      {:ok, [token], "", _} = Spf.Lexer.tokenize_spf("exp=%{d}.com")
      {:exp, [expand, literal], 0..11} = token
      assert {:expand, [?d, -1, false, ["."]], 4..7} == expand
      assert {:literal, [".com"], 8..11} == literal
    end

    test "02 - trailing dot is not dropped" do
      {:ok, [token], "", _} = Spf.Lexer.tokenize_spf("exp=%{d}.com.")
      {:exp, [expand, literal], 0..12} = token
      assert {:expand, [?d, -1, false, ["."]], 4..7} == expand
      assert {:literal, [".com."], 8..12} == literal
    end

    test "03 - toplabel check done by parser" do
      {:ok, [{:exp, [expand, literal], 0..12}], "", _} = Spf.Lexer.tokenize_spf("exp=%{d}.-com")
      assert {:expand, [?d, -1, false, ["."]], 4..7} == expand
      assert {:literal, [".-com"], 8..12} == literal
    end

    test "04 - catches invalid domspec" do
      {:ok, [{:exp, [expand, literal], 0..12}], "", _} = Spf.Lexer.tokenize_spf("exp=%{d}.com-")
      assert {:expand, [?d, -1, false, ["."]], 4..7} == expand
      assert {:literal, [".com-"], 8..12} == literal
    end
  end

  describe "redirect-modifier" do
    @describetag :tokens_redirect

    test "01 - domain-spec" do
      {:ok, [{:redirect, [expand, literal], 0..16}], "", _} =
        Spf.Lexer.tokenize_spf("redirect=%{d}.com")

      assert {:expand, [?d, -1, false, ["."]], 9..12} == expand
      assert {:literal, [".com"], 13..16} == literal
    end

    test "02 - trailing dot is not dropped" do
      {:ok, [{:redirect, [expand, literal], 0..17}], "", _} =
        Spf.Lexer.tokenize_spf("redirect=%{d}.com.")

      assert {:expand, [?d, -1, false, ["."]], 9..12} == expand
      assert {:literal, [".com."], 13..17} == literal
    end

    test "03 - some errors are caught" do
      {:ok, [{:redirect, [expand, literal, error, literal2], 0..17}], "", _} =
        Spf.Lexer.tokenize_spf("redirect=%{d}.c%m.")

      assert {:expand, [?d, -1, false, ["."]], 9..12} == expand
      assert {:literal, [".c"], 13..14} == literal
      assert {:error, ["%"], 15..15} == error
      assert {:literal, ["m."], 16..17} == literal2
    end

    test "04 - takes domspec literally" do
      {:ok, [{:redirect, [expand, literal], 0..17}], "", _} =
        Spf.Lexer.tokenize_spf("redirect=%{d}.1234")

      assert {:expand, [?d, -1, false, ["."]], 9..12} == expand
      assert {:literal, [".1234"], 13..17} == literal
    end
  end

  describe "version-modifier" do
    @describetag :tokens_version
    test "01 - version 1" do
      {:ok, [token], "", _} = Spf.Lexer.tokenize_spf("v=spf1")
      assert token == {:version, [1], 0..5}
    end

    test "02 - any version number" do
      {:ok, [token], "", _} = Spf.Lexer.tokenize_spf("v=spf11")
      assert token == {:version, [11], 0..6}
    end

    test "03 - case-insensitive" do
      {:ok, [token], "", _} = Spf.Lexer.tokenize_spf("V=SpF11")
      assert token == {:version, [11], 0..6}
    end
  end

  describe "errors" do
    @describetag :tokens_unknown

    test "01 - anything visible, including %" do
      {:ok, [token], "", _} = Spf.Lexer.tokenize_spf("pasthere%see?")
      assert token == {:error, ["pasthere%see?"], 0..12}
    end

    test "02 - anything visible, so stops at whitespace" do
      {:ok, [tok1, _whitespace, tok2], "", _} = Spf.Lexer.tokenize_spf("tillhere see?")
      {:error, ["tillhere"], 0..7} = tok1
      {:error, ["see?"], 9..12} = tok2

      {:ok, [tok1, _whitespace, tok2], "", _} = Spf.Lexer.tokenize_spf("tillhere\tsee?")
      {:error, ["tillhere"], 0..7} = tok1
      {:error, ["see?"], 9..12} = tok2
    end
  end

  describe "explain-string" do
    @describetag :tokens_exp_str
    # exp     = domain-spec
    #   ; after expansion & TXT-RR retrieval => exp_str
    # exp_str = *( macro-string / WSP )

    test "01 - simple explain-string" do
      {:ok, [{:exp_str, tokens, 0..10}], "", _} = Spf.Lexer.tokenize_exp("%{i} is bad")
      [tok0, _ws0, tok1, _ws1, tok2] = tokens
      assert {:expand, [?i, -1, false, ["."]], 0..3} == tok0
      assert {:literal, ["is"], 5..6} == tok1
      assert {:literal, ["bad"], 8..10} == tok2
    end

    test "02 - empty explain-string" do
      {:ok, [{:exp_str, [], @null_slice}], "", _} = Spf.Lexer.tokenize_exp("")
    end

    test "03 - only whitespace" do
      {:ok, [{:exp_str, [wspace], 0..2}], "", _} = Spf.Lexer.tokenize_exp("   ")
      assert {:whitespace, ["   "], 0..2} == wspace
    end

    test "04 - with fqdn name in it" do
      # note: trailing dot is not dropped
      str = "%{i} != example.com."
      {:ok, [{:exp_str, tokens, 0..19}], "", _} = Spf.Lexer.tokenize_exp(str)
      [tok0, _ws0, tok1, _ws1, tok2] = tokens
      assert {:expand, [?i, -1, false, ["."]], 0..3} == tok0
      assert {:literal, ["!="], 5..6} == tok1
      assert {:literal, ["example.com."], 8..19} == tok2
    end

    test "06 - with syntax error at the start" do
      {:ok, [{:exp_str, [err, _, l1, _, e1, l2], 0..11}], "", _} =
        Spf.Lexer.tokenize_exp("% good %{i}.")

      assert {:error, ["%"], 0..0} == err
      assert {:literal, ["good"], 2..5} == l1
      assert {:expand, [?i, -1, false, ["."]], 7..10} == e1
      assert {:literal, ["."], 11..11} == l2
    end

    test "06 - with syntax error in the middle" do
      {:ok, [{:exp_str, [l1, _, err, l2, _, l3], 0..15}], "", _} =
        Spf.Lexer.tokenize_exp("good %{bad} good")

      assert {:literal, ["good"], 0..3} == l1
      assert {:error, ["%"], 5..5} == err
      assert {:literal, ["{bad}"], 6..10} == l2
      assert {:literal, ["good"], 12..15} == l3
    end

    test "07 - with syntax error at the end" do
      {:ok, [{:exp_str, [l1, _, l2, _, l3, _, err, l4], 0..17}], "", _} =
        Spf.Lexer.tokenize_exp("not an expand %{z}")

      assert {:literal, ["not"], 0..2} == l1
      assert {:literal, ["an"], 4..5} == l2
      assert {:literal, ["expand"], 7..12} == l3
      assert {:error, ["%"], 14..14} == err
      assert {:literal, ["{z}"], 15..17} == l4
    end
  end
end
