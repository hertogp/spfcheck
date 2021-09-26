defmodule SpfcheckTestSuite do
  alias Rfc7208.TestSuite
  use ExUnit.Case

  Enum.each(TestSuite.all(), fn {test, mailfrom, helo, ip, result, dns, info} ->
    @test test
    # @mailfrom String.split(mailfrom, "@") |> List.last()
    @mailfrom mailfrom
    @helo helo
    @ip ip
    @result result
    @dns dns
    @info info
    @test_tag String.split(test, ".") |> List.first()

    @tag set: @test_tag
    test "#{@test} - #{@mailfrom}" do
      ctx =
        Spf.Context.new(@mailfrom, helo: @helo, ip: @ip)
        |> Spf.DNS.load_lines(@dns)
        |> Spf.Eval.evaluate()

      msg = "got #{ctx.verdict}, expected #{@result} - #{@info}\n" <> Enum.join(@dns, "\n")

      assert "#{ctx.verdict}" in @result, msg
    end
  end)
end
