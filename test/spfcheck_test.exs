defmodule SpfcheckTest do
  use ExUnit.Case
  doctest Spfcheck

  test "greets the world" do
    {:ok, list} = Spf.grep("example.com")
    assert list == ["v=spf1 -all"]
  end
end
