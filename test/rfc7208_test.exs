defmodule SpfcheckTestSuite do
  alias Rfc7208.TestSuite
  use ExUnit.Case

  Enum.each(TestSuite.all(), fn {test, mfrom, helo, ip, result, dns, info} ->
    @test test
    @mfrom String.split(mfrom, "@") |> List.last()
    @helo helo
    @ip ip
    @result result
    @dns dns
    @info info
    @test_tag String.split(test, ".") |> List.first()

    @tag set: @test_tag
    test "#{@test}" do
      ctx =
        Spf.Context.new(@mfrom, sender: @helo, ip: @ip)
        |> Spf.DNS.load_lines(@dns)
        |> Spf.grep()
        |> Spf.Parser.parse()
        |> IO.inspect(label: "#{@test}")
        |> Spf.Eval.eval()

      IO.inspect(ctx.dns, label: :dns)
      assert "#{ctx.verdict}" == @result, "#{ctx.verdict} != #{@result} - #{@info}"
    end
  end)
end
