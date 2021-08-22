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

    # a domain spec is a subtoken

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

    test "domain_spec stops at dual_cidr" do
      {:ok, [token], rest, _, _, _} = domain_spec("%{d}.com/24")

      assert token ==
               {:domain_spec, [{:expand, [?d, 0, false, ["."]], 0..3}, {:literal, ".com", 4..7}],
                0..7}

      assert rest == "/24"
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
               {:ok, [{:whitespace, [" "], 0..0}], "", %{start: 0}, {1, 0}, 1}
    end

    test "1+ spaces" do
      assert wspace("   ") ==
               {:ok, [{:whitespace, ["   "], 0..2}], "", %{start: 0}, {1, 0}, 3}
    end

    test "1+ tabs" do
      assert wspace("\t\t") ==
               {:ok, [{:whitespace, ["\t\t"], 0..1}], "", %{start: 0}, {1, 0}, 2}
    end

    test "1+ (SP / TAB)" do
      assert wspace(" \t ") ==
               {:ok, [{:whitespace, [" \t "], 0..2}], "", %{start: 0}, {1, 0}, 3}
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
end
