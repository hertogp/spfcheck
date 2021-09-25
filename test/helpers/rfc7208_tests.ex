defmodule Rfc7208.TestSuite do
  @rfc7208_tests Path.join(__DIR__, "rfc7208-tests-2014.05.yml")

  # For RFC 4408, the test suite was designed for use with SPF (type 99) and TXT
  # implementations.  In RFC 7208, use of type SPF has been removed.

  # The "Selecting records"
  # test section is the only one concerned with weeding out (incorrect) queries
  # for type SPF of any kind or proper response to duplicate or conflicting
  # records.  Other sections rely on auto-magic duplication of SPF to TXT
  # records (by test suite drivers) to test all implementation types with one
  # specification.

  # Tests
  # 0  - Initial processing
  # 1  - Record lookup
  # 2  - Selecting records     <- keep SPF as SPF, donot convert to TXT record
  # 3  - Record evaluation
  # 4  - ALL mechanism syntax
  # 5  - PTR mechanism syntax
  # 6  - A   mechanism syntax
  # 7  - Include mechanism syntax
  # 8  - MX  mechanism syntax
  # 9  - EXISTS mechanism syntax
  # 10 - IP4 mechanism syntax
  # 11 - IP6 mechanism syntax
  # 12 - Semantics of exp and other modifiers
  # 13 - Macro expansion rules
  # 14 - Processing limits

  def load_file() do
    {:ok, docs} = YamlElixir.read_all_from_file(@rfc7208_tests)
    docs
  end

  def all() do
    load_file()
    |> all_tests()
  end

  def all_tests(docs) do
    docs
    |> Enum.with_index()
    |> Enum.map(&to_tests/1)
    |> List.flatten()
  end

  def to_tests({doc, nth}) do
    desc = doc["description"]
    dns = doc["zonedata"] |> to_dns_lines(nth)
    tests = doc["tests"] |> Enum.with_index()

    for {test, mth} <- tests, do: to_test(test, desc, dns, nth, mth)
  end

  def to_test({name, test}, desc, dns, nth, mth) do
    spec = test["spec"] || ""
    helo = test["helo"]
    ip = test["host"]
    mailfrom = test["mailfrom"]
    result = test["result"]

    # desc2 = test["description"] || ""
    # comment = test["comment"] || ""

    info = Enum.join(["spec #{spec}", desc, name], " - ")
    {"#{nth}.#{mth} #{name}", mailfrom, helo, ip, result, dns, info}
  end

  def to_dns_lines(zdata, nth) do
    for {domain, rdata} <- zdata do
      for data <- rdata do
        [{type, value}] =
          case data do
            v when is_binary(v) -> [{"", v}]
            m when is_map(m) -> Map.to_list(m)
          end

        type = type_nth(type, nth)
        "#{domain} #{type} #{value}"
      end
    end
    |> List.flatten()
  end

  def type_nth(type, 2),
    # For category 2 Selecting Records, keep SPF as SPF
    do: type

  def type_nth(type, _) do
    case type do
      "SPF" -> "TXT"
      _ -> type
    end
  end
end
