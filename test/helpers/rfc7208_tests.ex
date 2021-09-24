defmodule Rfc7208.TestSuite do
  @rfc7208_tests Path.join(__DIR__, "rfc7208-tests-2014.05.yml")

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
    dns = doc["zonedata"] |> to_dns_cache()
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

    tdesc = Enum.join(["#{nth}.#{mth}", "spec #{spec}", desc, name], " - ")
    {tdesc, mailfrom, helo, ip, result, dns}
  end

  def to_dns_cache(zdata) do
    for {domain, rdata} <- zdata do
      for data <- rdata do
        [{type, value}] =
          case data do
            v when is_binary(v) -> [{"ALL", v}]
            m when is_map(m) -> Map.to_list(m)
          end

        {domain, type, value}
      end
    end
    |> List.flatten()
    |> Enum.into(%{}, fn {name, type, value} -> {{name, type}, value} end)
  end
end
