defmodule SpfcheckTest do
  use ExUnit.Case
  doctest Spfcheck

  test "001 - dns labels limited to 63 chars" do
    # for initial processing, a long label results in None, not TempError
    # spec: 4.3/1
    domain = "A123456789012345678901234567890123456789012345678901234567890123.example.com"
    sender = "lyme.eater@#{domain}"
    ip = "1.2.3.5"
    result = "none"

    zonedata = %{
      {"example.com", :txt} => {:error, :timeout}
    }

    ctx =
      Spf.Context.new(domain, sender: sender, ip: ip)
      |> Map.put(:dns, zonedata)
      |> Spf.grep()
      |> Spf.Parser.parse()
      |> Spf.Eval.eval()

    assert String.length(domain) > 63
    assert ctx.verdict == :none
  end

  test "002 - dns labels limited to 63 chars" do
    # for initial processing, a long label results in None, not TempError
    # spec: 4.3/1
    domain = "A12345678901234567890123456789012345678901234567890123456789012.example.com"
    sender = "lyme.eater@#{domain}"
    ip = "1.2.3.5"
    result = "none"

    zonedata = %{
      {"example.com", :txt} => {:error, :timeout},
      {"a12345678901234567890123456789012345678901234567890123456789012.example.com", :txt} => [
        "v=spf1 -all"
      ]
    }

    ctx =
      Spf.Context.new(domain, sender: sender, ip: ip)
      |> Map.put(:dns, zonedata)
      |> Spf.grep()
      |> Spf.Parser.parse()
      |> Spf.Eval.eval()

    assert String.length(domain) > 63
    assert ctx.verdict == :fail
  end
end
