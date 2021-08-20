defmodule Spf.TokenTest do
  use ExUnit.Case
  import NimbleParsec

  # Assertions
  # from https://elixirforum.com/t/trying-to-write-a-simple-nimble-parsec-parser/41344/4

  describe "macro combinator" do
    defparsecp(:macro, Spf.Tokens.macro())

    test "parses expands" do
      testcases = [
        "%{d}",
        "%{d}/32",
        "%{d}//128",
        "%{d}/32//128",
        "%{d}.co.uk.%{i}/24",
        "%{d}.a%-b"
      ]

      Enum.map(testcases, fn testcase -> IO.inspect(macro(testcase), label: testcase) end)
      {:ok, _, "", _, _, _} = macro("%{i}")
    end
  end
end
