defmodule Spf.ContextTest do
  use ExUnit.Case
  doctest Spf.Context, import: true

  @context Spf.Context.new("example.com")

  describe "spf_get" do
    @describetag :context_spf_get
    test "01 - non-existing spf by existing nth" do
      res = Spf.Context.get_spf(@context, 0)
      assert String.contains?(res, "ERROR")
      assert String.contains?(res, "NOT FOUND")
    end

    test "02 - non-existing spf by non-existing nth" do
      res = Spf.Context.get_spf(@context, 10)
      assert String.contains?(res, "ERROR")
      assert String.contains?(res, "NOT FOUND")
    end

    test "03 - non-existing spf by existing name" do
      res = Spf.Context.get_spf(@context, "example.com")
      assert String.contains?(res, "ERROR")
      assert String.contains?(res, "NOT FOUND")
    end

    test "04 - non-existing spf by existing name" do
      res = Spf.Context.get_spf(@context, "example.xyz")
      assert String.contains?(res, "ERROR")
      assert String.contains?(res, "NOT FOUND")
    end

    test "05 - non-existing spf by existing existing name with txt records" do
      res =
        @context
        |> Spf.DNS.load("example.com TXT not an spf record")
        |> Spf.Context.get_spf("example.com")

      assert String.contains?(res, "ERROR")
      assert String.contains?(res, "NOT FOUND")
    end
  end

  describe "addip - edge cases" do
    @describetag :context_addip
    test "01 - won't add bad ip" do
      res =
        @context
        |> Spf.Context.addip("1.1.1.400", [32, 128], "invalid IP")

      {nth, facility, severity, msg} = List.first(res.msg)

      # {nth, facility, severity, text}
      assert 0 == nth
      assert :ctx == facility
      assert :error == severity
      assert String.contains?(String.downcase(msg), "malformed")
    end
  end
end
