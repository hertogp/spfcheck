defmodule SpfcheckTest do
  alias Rfc7208.TestSuite
  use ExUnit.Case

  Enum.each(TestSuite.all(), fn {desc, mfrom, helo, ip, result, dns} ->
    @desc desc
    @mfrom mfrom
    @helo helo
    @ip ip
    @result result
    @dns dns
    test "#{desc}" do
      ctx =
        Spf.Context.new(@mfrom, sender: @helo, ip: @ip)
        |> Map.put(:dns, @dns)
        |> Spf.grep()
        |> Spf.Parser.parse()
        |> Spf.Eval.eval()

      IO.inspect(@dns, label: :dns)
      assert "#{ctx.verdict}" == @result, @desc <> " -> (#{ctx.verdict} != #{@result})"
    end
  end)
end
