defmodule Mix.Tasks.Rfc7208.Testsuite do
  use Mix.Task

  @moduledoc """
  Rfc7208 testsuite yaml definitions translated to ExUnit test files in test directory.

   See:
   - http://www.open-spf.org/Test_Suite/Schema/
   - http://www.open-spf.org/Test_Suite/

   ZoneData is map:
   - its keys are dns names
   - its values are lists of map's, each with a single entry
   - the key of the entry-map, is the RR-type
   - the value of the entry-map, is a string or list (eg for MX records)
     A value of a string is promoted to a list of 1 string

   DNS errors
   - TIMEOUT
     when the last entry for a dns name in the zonedata is TIMEOUT, then all
     non-specified RR's will result in a timeout

   - NONE
     when a TXT RR's value is none, the SPF record is NOT copied to the TXT RR
     this allows record selection testing (see below)

   - RCODE: n, is not used at the moment

   For RFC 4408, the test suite was designed for use with SPF (type 99) and TXT
   implementations.  In RFC 7208, use of type SPF has been removed.

   The "Selecting records"
   test section is the only one concerned with weeding out (incorrect) queries
   for type SPF of any kind or proper response to duplicate or conflicting
   records.  Other sections rely on auto-magic duplication of SPF to TXT
   records (by test suite drivers) to test all implementation types with one
   specification.

   Test sections
   0  - Initial processing
   1  - Record lookup
   2  - Selecting records     <- keep SPF as SPF, donot convert to TXT record
   3  - Record evaluation
   4  - ALL mechanism syntax
   5  - PTR mechanism syntax
   6  - A   mechanism syntax
   7  - Include mechanism syntax
   8  - MX  mechanism syntax
   9  - EXISTS mechanism syntax
   10 - IP4 mechanism syntax
   11 - IP6 mechanism syntax
   12 - Semantics of exp and other modifiers
   13 - Macro expansion rules
   14 - Processing limits
  """
  @shortdoc "Rfc7208 testsuite is created from the rfc's yaml file."

  @impl Mix.Task
  def run(args) do
    Mix.shell().info(Enum.join(args, " "))
    Mix.shell().info("Path is " <> Path.join("priv", "rfc7208-tests-2014.05.yml"))
    Mix.shell().info("Environment is " <> to_string(Mix.env()))
    all = all()
    Mix.shell().info(inspect(hd(all)))
  end

  # Implementation
  alias YamlElixir

  @rfc7208_tests Path.join("priv", "rfc7208-tests-2014.05.yml")
  @rrtypes ["A", "AAAA", "CNAME", "MX", "PTR", "SOA", "SPF", "TXT"]

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
    dns = doc["zonedata"] |> to_dns_lines()
    tests = doc["tests"] |> Enum.with_index()

    for {test, mth} <- tests, do: to_test(test, desc, dns, nth, mth)
  end

  def to_test({name, test}, desc, dns, nth, mth) do
    spec = test["spec"] || ""
    helo = test["helo"]
    ip = test["host"]
    mailfrom = test["mailfrom"]
    result = test["result"] |> List.wrap() |> Enum.map(&String.downcase/1)
    explanation = test["explanation"] || ""
    # set DEFAULT explanation to ""
    explanation = if explanation == "DEFAULT", do: "", else: explanation

    info = Enum.join(["spec #{spec}", desc, name], " - ")
    {"#{nth}.#{mth} #{name}", mailfrom, helo, ip, result, dns, info, explanation}
  end

  def to_dns_lines(zdata) do
    for {domain, rdata} <- zdata do
      for data <- rdata do
        case data do
          s when is_binary(s) -> {"OTHER", s}
          %{"MX" => [pref, host]} -> {"MX", "#{pref} #{host}"}
          m when is_map(m) -> Map.to_list(m) |> List.first()
        end
      end
      |> cp_spf()
      |> do_other()
      |> Enum.map(fn {type, data} -> "#{domain} #{type} #{data}" end)
    end
    |> List.flatten()
  end

  def cp_spf(rrs) do
    # http://www.open-spf.org/Test_Suite/Schema/
    # Records of type SPF get special treatment:
    # - If no records of type TXT are given for the same DNS name, then
    #   an identical TXT record is also generated for the DNS data.
    #   note: for all SPF records found
    # This reflects the recommendation of section 3.1.1 and allows the test
    # suite to be used with implementations that choose any of the three
    # options in section 4.4.

    # wtf?
    # In addition:
    # - when the value of an SPF name is the string NONE, then that record
    #   is not added to the DNS data.
    #
    # As a result, TXT: NONE serves to suppress the auto copy of SPF records to
    # TXT. This allows testing of record selection rules.
    # Ah, need to do cp_spf first, then w/ do_others, filter out any RR's that
    # have value NONE first

    copy = not Enum.any?(rrs, fn {type, _value} -> type == "TXT" end)

    spfs =
      Enum.filter(rrs, fn {k, v} -> k == "SPF" and v != "NONE" end)
      |> Enum.map(fn {_, v} -> {"TXT", v} end)

    none = Enum.filter(rrs, fn {_k, v} -> v == "NONE" end)

    if copy and length(spfs) > 0 do
      spfs ++ (rrs -- none)
    else
      rrs -- none
    end
  end

  def do_other(rrs) do
    # {"OTHER", value} -> causes the non-specified RRs to be added with value
    case List.keytake(rrs, "OTHER", 0) do
      nil -> rrs
      {{_, value}, rrs} -> add_others(rrs, value)
    end
  end

  def add_others(rrs, value) do
    # add {type, value} for types not included in rrs
    types = Enum.map(rrs, fn {type, _} -> String.upcase(type) end)
    others = @rrtypes -- types
    rrs ++ Enum.map(others, fn type -> {type, value} end)
  end
end
