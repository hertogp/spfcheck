defmodule SpfcheckTestSuite do
  alias Rfc7208.TestSuite
  use ExUnit.Case

  # usage:
  # mix test --only set:n, where n in 0..14
  # mix test --only tst:x.y where x.y is a specific test in the test suite

  Enum.each(TestSuite.all(), fn {test, mailfrom, helo, ip, result, dns, info, explanation} ->
    @test test
    @mailfrom mailfrom
    @helo helo
    @ip ip
    @result result
    @dns dns
    @info info
    @explanation explanation
    @test_set String.split(test, ".") |> List.first()
    @test_tag String.split(test, " ") |> List.first()

    @tag set: @test_set
    @tag tst: @test_tag
    test "#{@test} - #{@mailfrom}" do
      ctx = Spf.check(@mailfrom, helo: @helo, ip: @ip, dns: @dns)

      msg = "\ngot #{ctx.verdict}, expected #{@result} - #{@info}\n"
      msg = msg <> "got #{ctx.explanation}, expected #{@explanation}\n\n"
      msg = msg <> "TEST\n"
      msg = msg <> "- TEST: #{@test}\n"
      msg = msg <> "- FROM: #{@mailfrom}\n"
      msg = msg <> "- HELO: #{@helo}\n"
      msg = msg <> "- IP  : #{@ip}\n"

      msg = msg <> "\nCTX\n"
      msg = msg <> "- domain : #{ctx.domain}\n"
      msg = msg <> "- ip     : #{inspect(ctx.ip)}\n"
      msg = msg <> "- helo   : #{ctx.helo}\n"
      msg = msg <> "- spf    : #{inspect(ctx.spf)}\n"
      msg = msg <> "- Atype  : #{ctx.atype}\n"
      msg = msg <> "- verdict: #{ctx.verdict}\n"
      msg = msg <> "- reason : #{ctx.reason}\n"
      msg = msg <> "- error  : #{ctx.error}\n"
      msg = msg <> "- explain: #{inspect(ctx.explain)}\n"
      msg = msg <> "- expstr : #{ctx.explanation}\n"

      list = Enum.map(ctx.msg, fn x -> inspect(x) end)
      msg = msg <> "\nMSG\n"

      msg = msg <> (Enum.reverse(list) |> Enum.join("\n"))

      msg = msg <> "\n\nTOKENS\n"

      msg =
        msg <>
          (ctx.spf_tokens
           |> Enum.map(fn x -> inspect(x) end)
           |> Enum.join("\n"))

      msg = msg <> "\n\nAST\n"

      msg =
        msg <>
          (ctx.ast
           |> Enum.map(fn x -> inspect(x) end)
           |> Enum.join("\n"))

      msg = msg <> "\n\nDNS\n"
      want = fn l -> String.contains?(l, ctx.domain) or String.contains?(l, ctx.ip) end
      msg = msg <> (Enum.filter(@dns, fn l -> want.(l) end) |> Enum.join("\n"))

      msg = msg <> "\n\nMAP\n"

      msg =
        msg <>
          (for nth <- 0..(ctx.num_spf - 1) do
             "#{nth} - #{ctx.map[nth]}"
           end
           |> Enum.join("\n"))

      assert "#{ctx.verdict}" in @result, msg
      assert ctx.explanation == @explanation, msg
    end
  end)
end
