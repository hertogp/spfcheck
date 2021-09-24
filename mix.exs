defmodule Spfcheck.MixProject do
  use Mix.Project

  # Before publishing to Hex:
  # - update CHANGELOG.md for changes in new version
  # - set new version tag in mix.exs, README.md
  # - mix test
  # - mix docs
  # - mix dialyzer
  # - git tag -a vx.y.z -m 'Release vx.y.z'
  # - git push --tags
  # mix hex.publish

  @source_url "https://github.com/hertogp/spfcheck"
  @version "0.1.0"
  def project do
    [
      app: :spfcheck,
      version: @version,
      elixir: "~> 1.12",
      name: "Spfcheck",
      deps: deps(),
      docs: docs(),
      package: package(),
      aliases: aliases(),
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      escript: [main_module: Spfcheck]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    []
  end

  defp docs() do
    [
      extras: [
        "CHANGELOG.md": [],
        "LICENSE.md": [title: "License"],
        "README.md": [title: "Overview"]
      ],
      main: "readme",
      assets: "assets",
      source_url: @source_url,
      source_ref: "v#{@version}",
      formatters: ["html"]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:iptrie, "~> 0.5.0"},
      {:nimble_parsec, "~> 1.0"},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false},
      {:dialyxir, "~> 1.0", only: :dev, runtime: false},
      {:credo, "~> 0.8", only: [:dev, :test]},
      {:yaml_elixir, "~> 2.8.0", only: [:test]}
    ]
  end

  defp package do
    [
      description: "SPF checker for mail domains",
      licenses: ["MIT"],
      maintainers: ["hertogp"],
      links: %{
        "Changelog" => "https://hexdocs.pm/spfcheck/changelog.html",
        "GitHub" => @source_url
      }
    ]
  end

  defp aliases() do
    [
      docs: ["docs", &gen_images/1]
    ]
  end

  # process all assets/*.dot files into assets/*.dot.png image files
  defp gen_images(_) do
    for dot <- Path.wildcard("assets/*.dot") do
      System.cmd("dot", ["-O", "-Tpng", dot])
    end
  end
end
