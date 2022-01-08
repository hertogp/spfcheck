defmodule Rfc7208.Section15Test do
  use ExUnit.Case

  # Generated by mix rfc7208.testsuite
  # Usage:
  # % mix test
  # % mix test --only set:15
  # % mix test --only tst:15.y where y is in [0..0]

  describe "rfc7208-15-test-cases-from-implementation-bugs" do
    @tag set: "15"
    @tag tst: "15.0"
    test "15.0 bytes-bug" do
      # spec 5.4/4 - Test cases from implementation bugs - bytes-bug

      ctx =
        Spf.check("test@example.org",
          helo: "example.org",
          ip: "2001:db8:ff0:100::2",
          dns: "test/zones/rfc7208-15-test-cases-from-implementation-bugs.zonedata"
        )

      assert to_string(ctx.verdict) in ["pass"]
      assert ctx.explanation == ""
    end
  end
end
