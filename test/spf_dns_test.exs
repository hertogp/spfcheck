defmodule SpfDNSTest do
  use ExUnit.Case
  doctest Spf.DNS, import: true

  describe "DNS cache" do
    test "00 - caches zonedata from heredoc" do
      zonedata = """
      example.com A 1.2.3.4
      example.com AAAA 2001::1
      example.com MX 10 mail.example.com
      example.com TXT v=spf1 -all
      example.com SPF v=spf1 +all
      example.com ns ns.example.com
      4.3.2.1.in-addr.arpa ptr example.com
      example.com SOA ns.icann.org. noc.dns.icann.org. 2021120710 7200 3600 1209600 3600
      example.net CNAME example.org
      example.org A 1.1.1.1
      """

      ctx = Spf.Context.new("example.com", dns: zonedata)

      {_ctx, result} = Spf.DNS.resolve(ctx, "example.com", type: :a)
      assert result == {:ok, ["1.2.3.4"]}

      # ipv6 formatting is produced by Pfx
      {_ctx, result} = Spf.DNS.resolve(ctx, "example.com", type: :aaaa)
      assert result == {:ok, ["2001:0:0:0:0:0:0:1"]}

      {_ctx, result} = Spf.DNS.resolve(ctx, "example.com", type: :mx)
      assert result == {:ok, [{10, "mail.example.com"}]}

      {_ctx, result} = Spf.DNS.resolve(ctx, "example.com", type: :txt)
      assert result == {:ok, ["v=spf1 -all"]}

      {_ctx, result} = Spf.DNS.resolve(ctx, "example.com", type: :spf)
      assert result == {:ok, ["v=spf1 +all"]}

      {_ctx, result} = Spf.DNS.resolve(ctx, "example.com", type: :ns)
      assert result == {:ok, ["ns.example.com"]}

      {_ctx, result} = Spf.DNS.resolve(ctx, "4.3.2.1.in-addr.arpa", type: :ptr)
      assert result == {:ok, ["example.com"]}

      {_ctx, result} = Spf.DNS.resolve(ctx, "example.com", type: :soa)

      # note: names are normalized when entered into the cache so trailing dot
      # is dropped
      assert result ==
               {:ok,
                [
                  {
                    "ns.icann.org",
                    "noc.dns.icann.org",
                    2_021_120_710,
                    7200,
                    3600,
                    1_209_600,
                    3600
                  }
                ]}

      {_ctx, result} = Spf.DNS.resolve(ctx, "example.net", type: :cname)
      assert result == {:ok, ["example.org"]}

      # cname really works ..
      {_ctx, result} = Spf.DNS.resolve(ctx, "example.net", type: :a)
      assert result == {:ok, ["1.1.1.1"]}
    end

    test "01 - DNS cache from a list of lines" do
      zonedata =
        """
        example.com A 1.2.3.4
        example.com AAAA 2001::1
        example.com MX 10 mail.example.com
        example.com TXT v=spf1 -all
        example.com SPF v=spf1 +all
        example.com ns ns.example.com
        4.3.2.1.in-addr.arpa ptr example.com
        example.com SOA ns.icann.org. noc.dns.icann.org. 2021120710 7200 3600 1209600 3600
        example.net CNAME example.org
        example.org A 1.1.1.1
        """
        |> String.split("\n")

      ctx = Spf.Context.new("example.com", dns: zonedata)

      {_ctx, result} = Spf.DNS.resolve(ctx, "example.com", type: :a)
      assert result == {:ok, ["1.2.3.4"]}

      # resolve() defaults type to :a
      {_ctx, result} = Spf.DNS.resolve(ctx, "example.com")
      assert result == {:ok, ["1.2.3.4"]}

      # ipv6 formatting is produced by Pfx
      {_ctx, result} = Spf.DNS.resolve(ctx, "example.com", type: :aaaa)
      assert result == {:ok, ["2001:0:0:0:0:0:0:1"]}

      {_ctx, result} = Spf.DNS.resolve(ctx, "example.com", type: :mx)
      assert result == {:ok, [{10, "mail.example.com"}]}

      {_ctx, result} = Spf.DNS.resolve(ctx, "example.com", type: :txt)
      assert result == {:ok, ["v=spf1 -all"]}

      {_ctx, result} = Spf.DNS.resolve(ctx, "example.com", type: :spf)
      assert result == {:ok, ["v=spf1 +all"]}

      {_ctx, result} = Spf.DNS.resolve(ctx, "example.com", type: :ns)
      assert result == {:ok, ["ns.example.com"]}

      {_ctx, result} = Spf.DNS.resolve(ctx, "4.3.2.1.in-addr.arpa", type: :ptr)
      assert result == {:ok, ["example.com"]}

      {_ctx, result} = Spf.DNS.resolve(ctx, "example.com", type: :soa)

      # note: names are normalized when entered into the cache so trailing dot
      # is dropped
      assert result ==
               {:ok,
                [
                  {
                    "ns.icann.org",
                    "noc.dns.icann.org",
                    2_021_120_710,
                    7200,
                    3600,
                    1_209_600,
                    3600
                  }
                ]}

      {_ctx, result} = Spf.DNS.resolve(ctx, "example.net", type: :cname)
      assert result == {:ok, ["example.org"]}

      # cname really works ..
      {_ctx, result} = Spf.DNS.resolve(ctx, "example.net", type: :a)
      assert result == {:ok, ["1.1.1.1"]}
    end

    test "02 - dns cache from non-existing file" do
      # feed Spf.DNS.load the current working dir -> File.read will yield an
      # {:error, :eisdir}
      ctx =
        Spf.Context.new("some.tld")
        |> Spf.DNS.load(".")

      Enum.any?(ctx.msg, fn msg -> elem(msg, 3) |> String.contains?(":eisdir") end)
    end

    test "03 - dns cache rr-errors overwrite always" do
      zonedata = """
      example.com A 1.2.3.4
      example.com AAAA acdc:1976::1
      example.com AAAA Timeout
      example.com mx ServFail
      example.com mx 10 mail.example.com
      """

      ctx = Spf.Context.new("example.com", dns: zonedata)

      # the A record stays untouched
      {_ctx, {:ok, ["1.2.3.4"]}} = Spf.DNS.resolve(ctx, "example.com", type: :a)

      # the AAAA record has the error
      {_ctx, {:error, :timeout}} = Spf.DNS.resolve(ctx, "example.com", type: :aaaa)

      # unspecified (known) RR-types are set to SERVFAIL
      {_ctx, {:error, :servfail}} = Spf.DNS.resolve(ctx, "example.com", type: :mx)
    end

    test "04 - circular cname's yield :servfail" do
      zonedata = """
      example.com cname example.org
      example.com a 1.1.1.1
      example.org cname example.net
      example.org a 2.2.2.2
      example.net cname example.com
      example.net a 3.3.3.3
      """

      ctx = Spf.Context.new("some.tld", dns: zonedata)

      # straight cname resolving works
      {ctx, result} = Spf.DNS.resolve(ctx, "example.com", type: :cname)
      assert result == {:ok, ["example.org"]}
      {ctx, result} = Spf.DNS.resolve(ctx, "example.org", type: :cname)
      assert result == {:ok, ["example.net"]}
      {_ctx, result} = Spf.DNS.resolve(ctx, "example.net", type: :cname)
      assert result == {:ok, ["example.com"]}

      # circular CNAMEs yield :servfail (is a zonedata error)
      # rfc1035 - servfail: name server was unable to process the query due to
      # a (database) problem with the name server.

      {ctx, result} = Spf.DNS.resolve(ctx, "example.com", type: :a)
      assert result == {:error, :servfail}
      {ctx, result} = Spf.DNS.resolve(ctx, "example.com", type: :mx)
      assert result == {:error, :servfail}

      {ctx, result} = Spf.DNS.resolve(ctx, "example.org", type: :a)
      assert result == {:error, :servfail}
      {ctx, result} = Spf.DNS.resolve(ctx, "example.org", type: :mx)
      assert result == {:error, :servfail}

      {_ctx, result} = Spf.DNS.resolve(ctx, "example.net", type: :a)
      assert result == {:error, :servfail}
      {_ctx, result} = Spf.DNS.resolve(ctx, "example.net", type: :mx)
      assert result == {:error, :servfail}
    end

    test "05 - updating cache w/ timeout error overwrites" do
      zonedata = """
      example.com TXT some text record
      """

      ctx = Spf.Context.new("some.tld", dns: zonedata)
      ctx = Spf.DNS.load(ctx, "example.com TXT TIMEOUT")

      {_ctx, result} = Spf.DNS.resolve(ctx, "example.com", type: :txt)
      assert {:error, :timeout} == result
    end

    test "06 - updating cache w/ servfail error overwrites" do
      zonedata = """
      example.com TXT some text record
      """

      ctx = Spf.Context.new("some.tld", dns: zonedata)
      ctx = Spf.DNS.load(ctx, "example.com TXT SERVFAIL")

      {_ctx, result} = Spf.DNS.resolve(ctx, "example.com", type: :txt)
      assert {:error, :servfail} == result
    end

    test "07 - unsupported RR type" do
      zonedata = """
      example.com XYZ an unknown RR type
      """

      ctx = Spf.Context.new("some.tld", dns: zonedata)

      assert Enum.any?(ctx.msg, fn entry -> elem(entry, 3) |> String.contains?("malformed RR") end)
    end

    test "08 - cname's with errors" do
      zonedata = """
      example.com cname example.org
      example.org cname timeout
      """

      ctx = Spf.Context.new("some.tld", dns: zonedata)
      {_ctx, result} = Spf.DNS.resolve(ctx, "example.com", type: :a)
      assert {:error, :timeout} == result
    end

    test "09 - trying to resolve an unknown rr-type" do
      zonedata = """
      example.com a 1.2.3.4
      """

      ctx = Spf.Context.new("some.tld", dns: zonedata)
      {_ctx, result} = Spf.DNS.resolve(ctx, "example.com", type: :xyz)
      assert {:error, :unknown_rr_type} == result
    end

    test "10 - trying to resolve an illegal name" do
      zonedata = """
      example.com a 1.2.3.4
      """

      ctx = Spf.Context.new("some.tld", dns: zonedata)
      {_ctx, result} = Spf.DNS.resolve(ctx, "example..com", type: :xyz)
      assert {:error, :illegal_name} == result
    end

    test "11 - trying to resolve an not-implemented" do
      # test error response similar to servfail, in this case:
      # {:error, {:notimp, dns_msg}}
      ctx = Spf.Context.new("some.tld")
      {_ctx, result} = Spf.DNS.resolve(ctx, "example.com", type: :mf)
      assert {:error, :notimp} == result
    end

    test "12 - a zonedata's soa record should be correct" do
      zonedata = """
      example.com. soa ns.example.com noc.example.com 1 2 3 4 five
      example.org  soa ns.example.123 noc.example.com 1 2 3 4 5
      """

      ctx = Spf.Context.new("some.tld", dns: zonedata)

      assert Enum.any?(ctx.msg, fn msg -> elem(msg, 3) |> String.contains?("illegal ttl") end)
    end
  end

  describe "dns cache to lines" do
    test "01 - mx records" do
      zonedata = """
      example.com. mx 10 mail.example.com
      """

      # note:
      # - trailing dot should be removed
      # - mx becomes MX

      lines =
        Spf.Context.new("some.tld", dns: zonedata)
        |> Spf.DNS.to_list()

      assert ["example.com MX 10 mail.example.com"] == lines
    end

    test "02 - spf records" do
      # although not used for evaluation, they are supported in Spf.DNS cache
      zonedata = """
      example.com. spf v=spf1 -all
      """

      # note:
      # - trailing dot should be removed
      # - spf becomes SPF

      lines =
        Spf.Context.new("some.tld", dns: zonedata)
        |> Spf.DNS.to_list()

      assert ["example.com SPF v=spf1 -all"] == lines
    end

    test "03 - when someone messed up the context.dns cache manually" do
      # note:
      # - trailing dot should be removed
      # - a becomes A

      lines =
        Spf.Context.new("some.tld")
        |> Map.put(:dns, %{{"example.com", :a} => ["1.1.1.400"]})
        |> Spf.DNS.to_list()

      assert ["example.com A 1.1.1.400"] == lines
    end

    test "04 - when someone messed up the zonedata" do
      zonedata = """
      example.com a 1.1.1.400
      """

      ctx = Spf.Context.new("some.tld", dns: zonedata)
      assert Enum.any?(ctx.msg, fn entry -> elem(entry, 3) |> String.contains?("RR ignored") end)

      assert Enum.any?(ctx.msg, fn entry ->
               elem(entry, 3) |> String.contains?("illegal address")
             end)
    end

    test "05 - when someone messed up the zonedata" do
      zonedata = """
      example.com aaaa acdc:1976:defg
      """

      ctx = Spf.Context.new("some.tld", dns: zonedata)
      assert Enum.any?(ctx.msg, fn entry -> elem(entry, 3) |> String.contains?("RR ignored") end)

      assert Enum.any?(ctx.msg, fn entry ->
               elem(entry, 3) |> String.contains?("illegal address")
             end)
    end

    test "06 - when someone messed up the zonedata" do
      zonedata = """
      example.com aaaa 11-22-33-44-55-66
      """

      ctx = Spf.Context.new("some.tld", dns: zonedata)
      assert Enum.any?(ctx.msg, fn entry -> elem(entry, 3) |> String.contains?("RR ignored") end)

      assert Enum.any?(ctx.msg, fn entry ->
               elem(entry, 3) |> String.contains?("illegal address")
             end)
    end
  end
end
