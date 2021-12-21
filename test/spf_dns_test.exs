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

      # IPv6 formatting is produced by Pfx
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

    test "01 - dns cache should insert errors properly" do
      zonedata = """
      example.com A 1.2.3.4
      example.com AAAA TIMEOUT
      example.com SERVFAIL
      """

      ctx = Spf.Context.new("example.com", dns: zonedata)

      {_ctx, {:ok, ["1.2.3.4"]}} = Spf.DNS.resolve(ctx, "example.com", type: :a)

      {_ctx, {:error, :timeout}} = Spf.DNS.resolve(ctx, "example.com", type: :aaaa)

      {_ctx, {:error, :servfail}} = Spf.DNS.resolve(ctx, "example.com", type: :mx)
      {_ctx, {:error, :servfail}} = Spf.DNS.resolve(ctx, "example.com", type: :ns)
      {_ctx, {:error, :servfail}} = Spf.DNS.resolve(ctx, "example.com", type: :soa)
    end
  end
end
