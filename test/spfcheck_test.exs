defmodule SpfcheckTest do
  use ExUnit.Case
  import ExUnit.CaptureIO

  # standard args using -d to keep things local during testing

  @soa "example.com soa ns.example.com dns.example.com 1 2 3 4 5"
  @dns ["-d", "example.com txt v=spf1 +all\n#{@soa}"]
  @args ["example.com" | @dns]

  defp spfcheck_verdict(args) do
    # captures stdout and returns verdict lines as a map
    # downcase the keys, just to be sure
    transform = fn
      [x] -> {String.trim(x) |> String.downcase(), ""}
      [x, v] -> {String.trim(x) |> String.downcase(), String.trim(v)}
    end

    capture_io(fn ->
      capture_io(:stderr, fn -> Spfcheck.main(args) end)
    end)
    |> String.split("\n", trim: true)
    |> Enum.map(fn s -> String.split(s, ":", parts: 2, trim: true) end)
    |> Enum.into(%{}, transform)
  end

  defp spfcheck_stdout(args) do
    # run spfcheck and capture stderr
    capture_io(:stdio, fn ->
      capture_io(:stderr, fn -> Spfcheck.main(args) end)
    end)
  end

  defp spfcheck_stderr(args) do
    # run spfcheck and capture stderr
    capture_io(:stderr, fn ->
      capture_io(:stdio, fn -> Spfcheck.main(args) end)
    end)
  end

  describe "spfcheck warnings" do
    test "01 - less specific, no conflict" do
      dns = """
      example.com txt v=spf1 a a/24 -all
      example.com a 1.2.3.4
      """

      res =
        spfcheck_stderr(["example.com", "-d", dns])
        |> String.downcase()

      assert String.contains?(res, "more specific")
    end

    test "02 - less specific, with conflict" do
      dns = """
      example.com txt v=spf1 a -a/24 -all
      example.com a 1.2.3.4
      """

      res =
        spfcheck_stderr(["example.com", "-d", dns])
        |> String.downcase()

      assert String.contains?(res, "more specific")
      assert String.contains?(res, "inconsistent")
    end
  end

  describe "spfcheck - weird dns" do
    test "01 - txt RR has servfail" do
      dns = """
      example.com txt SERVFAIL
      """

      res =
        spfcheck_stderr(["example.com", "-d", dns])
        |> String.downcase()

      assert String.contains?(res, "spf[0]-eval-error")
      assert String.contains?(res, "servfail")
    end
  end

  describe "spfcheck --ip flag" do
    # resolves against real DNS
    test "001 - default ip" do
      res = spfcheck_verdict(@args)
      assert "127.0.0.1" == res["ip"]
    end

    test "002 - domain ipv4" do
      res = spfcheck_verdict(@args ++ ["-i", "1.2.3.4"])
      assert "1.2.3.4" == res["ip"]
    end

    test "003 - domain ipv6" do
      res = spfcheck_verdict(@args ++ ["-i", "acdc:1976::1"])
      assert "acdc:1976:0:0:0:0:0:1" == res["ip"]
    end

    test "004 - domain ipv4-mapped ipv6" do
      res = spfcheck_verdict(@args ++ ["-i", "::ffff:1.2.3.4"])
      assert "1.2.3.4" == res["ip"]
    end

    test "005 - illegal ipv4" do
      res = spfcheck_verdict(@args ++ ["-i", "1.2.3.400"])
      assert "127.0.0.1" == res["ip"]
    end

    test "006 - illegal ipv6" do
      res = spfcheck_verdict(@args ++ ["-i", "acdc:1976::beer"])
      assert "127.0.0.1" == res["ip"]
    end

    test "007 - illegal ipv4-mapped ipv6" do
      res = spfcheck_verdict(@args ++ ["-i", "::ffff:1.2.3.400"])
      assert "127.0.0.1" == res["ip"]
    end
  end

  describe "spfcheck from stdin" do
    res =
      capture_io("example.com", fn -> Spfcheck.main(["-v", "0" | @dns]) end)
      |> String.split("\n", trim: true)

    assert 2 == length(res)
    assert String.contains?(List.last(res), ":pass")
  end

  describe "spfcheck --verbose flag" do
    test "001 - queit" do
      res = spfcheck_stderr(["-v", "0" | @args])
      assert "" == res
    end

    test "002 - error" do
      dns = "example.com txt v=spf1 a/33 -all"
      res = spfcheck_stderr(["-v", "1", "-d", dns, "example.com"])
      assert String.contains?(res, "spf[0]-parse-error")
    end

    test "003 - warning" do
      dns = "example.com txt v=spf1 +all"
      res = spfcheck_stderr(["-v", "2", "-d", dns, "example.com"])
      assert String.contains?(res, "spf[0]-parse-warn")
    end

    test "004 - note" do
      dns = "example.com txt v=spf1 +all"
      res = spfcheck_stderr(["-v", "3", "-d", dns, "example.com"])
      assert String.contains?(res, "spf[0]-eval-note")
    end

    test "005 - info" do
      dns = "example.com txt v=spf1 +all\n#{@soa}"
      res = spfcheck_stderr(["-v", "4", "-d", dns, "example.com"])
      assert String.contains?(res, "spf[0]-ctx-info")
    end

    test "006 - debug" do
      dns = "example.com txt v=spf1 +all\n#{@soa}"
      res = spfcheck_stderr(["-v", "5", "-d", dns, "example.com"])
      assert String.contains?(res, "spf[0]-ctx-debug")
    end
  end

  describe "spfcheck --no-color" do
    test "001 - no colors" do
      res = spfcheck_stderr(["-v", "5", "--no-color" | @args])
      # no ANSI escapes in syslog id
      assert String.contains?(res, " %spf[0]-ctx-debug: ")
    end
  end

  describe "spfcheck --report" do
    # vgsewpdat
    test "001 - verdict" do
      res = spfcheck_stdout(["-v", "0", "-r", "v" | @args])
      # no ANSI escapes in syslog id
      assert String.contains?(res, "pass")
      assert String.contains?(res, "dns@example.com")
    end

    test "002 - graph" do
      res = spfcheck_stdout(["-v", "0", "-r", "g" | @args])
      # no ANSI escapes in syslog id
      assert String.contains?(res, "digraph")
      assert String.contains?(res, "dns@example.com")

      res = spfcheck_stdout(["-d", "assets/example.db", "-v", "0", "-r", "g", "example.com"])
      assert String.contains?(res, "digraph")
      assert String.contains?(res, "errors")
      assert String.contains?(res, "warnings")

      # use soa with error
      dns = """
      example.com txt v=spf1 -all"
      example.com soa servfail
      """

      res = spfcheck_stdout(["-d", dns, "-v", "0", "-r", "g", "example.com"])
      assert String.contains?(res, "digraph")
      # contact cannot be found
      assert String.contains?(res, "nxdomain")
    end

    test "002 - graph with include/redirect with macros" do
      dns = """
      # cache satifies all queries needed
      example.com txt v=spf1 include:%{d1r}.org redirect=%{d1r}.net"
      example.org txt v=spf1 ?all
      example.net txt v=spf1 -all
      example.com soa ns.example.com xxx.example.com 1 2 3 4 5
      example.org soa ns.example.com xxx.example.org 1 2 3 4 5
      example.net soa ns.example.com xxx.example.net 1 2 3 4 5
      """

      res = spfcheck_stdout(["-d", dns, "-v", "0", "-r", "g", "example.com"])
      # links point to expanded names of spf[0] macro terms
      assert String.contains?(res, "\"example.com\":\"0\" -> \"example.org\":\"TOP\";")
      assert String.contains?(res, "\"example.com\":\"1\" -> \"example.net\":\"TOP\";")
    end

    test "002 - graph with include without an spf record but with soa" do
      # just so we exercise the code paths for non-spf referalls
      dns = """
      # cache satifies all queries needed
      example.com txt v=spf1 include:example.org -all"
      example.org txt nxdomain
      example.org soa ns.example.org xxx.example.org 1 2 3 4 5
      """

      res = spfcheck_stdout(["-d", dns, "-v", "0", "-r", "g", "example.com"])
      # links point to expanded names of spf[0] macro terms
      assert String.contains?(res, "\"example.com\":\"0\" -> \"example.org\":\"TOP\";")
      assert String.contains?(res, "xxx@example.org")
      assert String.contains?(res, "NO SPF")
    end

    test "002 - graph with include without an spf record and no soa" do
      # just so we exercise the code paths for non-spf referalls
      dns = """
      # cache satifies all queries needed
      example.com txt v=spf1 include:example.org -all"
      example.org txt nxdomain
      example.org soa nxdomain
      """

      res = spfcheck_stdout(["-d", dns, "-v", "0", "-r", "g", "example.com"])
      # links point to expanded names of spf[0] macro terms
      assert String.contains?(res, "\"example.com\":\"0\" -> \"example.org\":\"TOP\";")
      assert String.contains?(res, "nxdomain")
      assert String.contains?(res, "NO SPF")
    end

    test "003 - spf" do
      res = spfcheck_stdout(["-v", "0", "-r", "s" | @args])
      # no ANSI escapes in syslog id
      assert String.contains?(res, "v=spf1 +all")
      assert String.contains?(res, "[0] example.com")

      # use soa with error
      dns = """
      example.com txt v=spf1 -all"
      example.com soa servfail
      """

      res = spfcheck_stdout(["-d", dns, "-v", "0", "-r", "s", "example.com"])
      assert String.contains?(res, "nxdomain")
    end

    test "004 - errors" do
      dns = "example.com txt v=spf1 a/33 -all"
      res = spfcheck_stdout(["-v", "0", "-r", "e", "-d", dns, "example.com"])
      assert String.contains?(res, "spf[0]-parse-error")
    end

    test "005 - warnings" do
      dns = "example.com txt v=spf1 +all"
      res = spfcheck_stdout(["-v", "0", "-r", "w", "-d", dns, "example.com"])
      assert String.contains?(res, "spf[0]-parse-warn")
    end

    test "006 - prefixes" do
      dns = "example.com txt v=spf1 ip4:1.2.3.0/24 ip6:acdc:1976::/32 -all"
      res = spfcheck_stdout(["-v", "0", "-r", "p", "-d", dns, "example.com"])
      assert String.contains?(res, "1.2.3.0/24")
      assert String.contains?(res, "acdc:1976:0:0:0:0:0:0/32")
    end

    test "007 - dns" do
      res = spfcheck_stdout(["-v", "0", "-r", "d" | @args])
      # check via artificial soa record, setting contact
      assert String.contains?(res, "dns.example.com")

      res =
        spfcheck_stdout(["-v", "0", "-r", "d", "-m", "-d", "assets/example.db", "example.com"])

      assert String.contains?(res, "## DNS issues")
    end

    test "008 - ast" do
      dns = "example.com txt v=spf1 ip4:1.2.3.0/24 ip6:acdc:1976::/32 -all"
      res = spfcheck_stdout(["-v", "0", "-r", "a", "-d", dns, "example.com"])
      refute String.contains?(res, ":version")
      refute String.contains?(res, ":whitespace")
      assert String.contains?(res, ":ip4")
      assert String.contains?(res, ":ip6")
      assert String.contains?(res, ":all")
    end

    test "008 - tokens" do
      dns = "example.com txt v=spf1 ip4:1.2.3.0/24 ip6:acdc:1976::/32 -all\n#{@soa}"
      res = spfcheck_stdout(["-v", "0", "-r", "t", "-d", dns, "example.com"])
      assert String.contains?(res, ":version")
      assert String.contains?(res, ":whitespace")
      assert String.contains?(res, ":ip4")
      assert String.contains?(res, ":ip6")
      assert String.contains?(res, ":all")
    end

    test "009 - all" do
      dns = "example.com txt v=spf1 ip4:1.2.3.0/24 ip6:acdc:1976::/32 -all\n#{@soa}"
      res = spfcheck_stdout(["-v", "0", "-r", "all", "-d", dns, "example.com"])
      assert String.contains?(res, "title")
      assert String.contains?(res, "author")
      assert String.contains?(res, "date")
      assert String.contains?(res, "## Verdict")
      assert String.contains?(res, "## Graphviz")
      assert String.contains?(res, "## SPF")
      assert String.contains?(res, "## Errors")
      assert String.contains?(res, "## Warnings")
      assert String.contains?(res, "## Prefixes")
      assert String.contains?(res, "## DNS")
      assert String.contains?(res, "## AST")
      assert String.contains?(res, "## Tokens")
    end

    test "010 - unknown topic ignored" do
      dns = "example.com txt v=spf1 ip4:1.2.3.0/24 ip6:acdc:1976::/32 -all\n#{@soa}"
      res = spfcheck_stdout(["-v", "0", "-r", "x", "-d", dns, "example.com"])
      assert String.contains?(res, "topic x ignored")
    end
  end

  describe "spfcheck help flag" do
    test "-H" do
      exit =
        catch_exit do
          spfcheck_stdout(["-H"])
        end

      assert exit == {:shutdown, 1}
    end
  end

  describe "spfcheck width flag" do
    test "001 - 10 wrapping point" do
      dns = "example.com txt v=spf1 ip4:1.1.1.0/24 ip4:1.1.2/24 ip6:acdc:1976::/32 -all\n#{@soa}"

      res =
        spfcheck_stdout(["-v", "0", "-r", "d", "-w", "18", "-d", dns, "example.com"])
        |> String.split("\n", trim: true)
        |> Enum.map(&String.length/1)

      # wrap at 18 or so, but allow for the offset
      refute Enum.any?(res, fn len -> len > 5 + 18 end)
    end
  end

  describe "spfcheck nameserver flag" do
    test "01 - google ipv4 dns" do
      # use cache
      dns = "example.com txt v=spf1 ip4:1.1.1.0/24 ip4:1.1.2/24 ip6:acdc:1976::/32 -all\n#{@soa}"

      res =
        spfcheck_stderr(["-v", "5", "-n", "8.8.8.8", "-n", "8.8.4.4", "-d", dns, "example.com"])

      assert String.contains?(res, "{{8, 8, 8, 8}, 53}")
      assert String.contains?(res, "{{8, 8, 4, 4}, 53}")
    end

    test "02 - google ipv4 dns" do
      # use google's dns
      res = spfcheck_stderr(["-v", "5", "-n", "8.8.8.8", "-n", "8.8.4.4", "example.com"])

      assert String.contains?(res, "{{8, 8, 8, 8}, 53}")
      assert String.contains?(res, "{{8, 8, 4, 4}, 53}")
      assert String.contains?(res, "verdict fail")
    end
  end

  describe "spfcheck batch mode" do
    test "001 - from stdin" do
      stdin = """
      # See assets/example.db

      example.com
      example.com
      example.com
      example.com
      """

      res =
        capture_io(stdin, fn ->
          Spfcheck.main(["-v", "0", "-b", "2", "-d", "assets/example.db"])
        end)

      assert String.contains?(res, "spf-c.example.com")
      assert String.contains?(res, "temperror")
      assert String.contains?(res, "timeout")
    end
  end
end
