defmodule SpfcheckTest do
  use ExUnit.Case
  doctest Spfcheck

  test "001 - dns labels limited to 63 chars" do
    # for initial processing, a long label results in None, not TempError
    # spec: 4.3/1
    domain = "A123456789012345678901234567890123456789012345678901234567890123.example.com"
    sender = "lyme.eater@#{domain}"
    ip = "1.2.3.5"

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

  Enum.each([{0, true, false}, {1, false, false}, {2, true, true}, {3, false, true}], fn {n, lhs,
                                                                                          rhs} ->
    @lhs lhs
    @rhs rhs
    @n n
    test "Test #{@n} - another test with a message" do
      msg = "lhs #{@lhs}, rhs #{@rhs}?"
      assert @lhs == @rhs, msg
    end
  end)

  @rfc7208_tests Path.join(__DIR__, "rfc7208-tests-2014.05.yml")

  @do_test fn zdata ->
    for {domain, rdata} <- zdata do
      IO.puts("#{domain}")

      for data <- rdata do
        [{type, value}] =
          case data do
            v when is_binary(v) -> [{"ALL", v}]
            m when is_map(m) -> Map.to_list(m)
          end

        IO.puts("- #{domain} #{type} #{value}")
      end
    end
  end
  @do_doc fn {doc, nth} ->
    desc = doc["description"]
    tests = doc["tests"]
    zdata = doc["zonedata"]
    IO.puts("#{nth} - #{desc}")

    tests
    |> Map.keys()
    |> Enum.with_index()
    |> Enum.each(fn {test, n} ->
      IO.puts("#{nth}.#{n} - #{desc} - #{test} tests, #{map_size(zdata)} domains")
      @do_test.(zdata)
    end)
  end

  # read test suite
  {:ok, docs} = YamlElixir.read_all_from_file(@rfc7208_tests)
  IO.puts("read #{length(docs)} docs from #{@rfc7208_tests})")

  docs
  |> Enum.with_index()
  |> Enum.each(@do_doc)
end
