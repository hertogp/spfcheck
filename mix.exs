defmodule Spfcheck.MixProject do
  use Mix.Project

  # Before publishing to Hex:
  # - update CHANGELOG.md for changes in new version
  # - set new version tag in mix.exs, README.md, CHANGELOG.md
  # - git is up-to-date
  # - github workflows are ok
  # - mix docs
  # - mix test
  # - mix dialyzer
  # - check doc (links working?)
  # - git tag -a vx.y.z -m 'Release vx.y.z'
  # - git push --tags
  # mix hex.publish

  @source_url "https://github.com/hertogp/spfcheck"
  @version "0.5.0"
  def project do
    [
      app: :spfcheck,
      version: @version,
      elixir: "~> 1.12",
      name: "Spfcheck",
      description: "command line tool to examine and debug SPF records",
      docs: docs(),
      deps: deps(),
      package: package(),
      aliases: aliases(),
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      escript: [main_module: Spfcheck],
      elixirc_paths: elixirc_paths(Mix.env())
    ]
  end

  defp elixirc_paths(:test),
    do: ["lib", "test/helpers"]

  defp elixirc_paths(_),
    do: ["lib"]

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
      source_url: @source_url,
      source_ref: "v#{@version}",
      assets: "assets",
      formatters: ["html"]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:iptrie, "~> 0.5.0"},
      {:nimble_parsec, "~> 1.0"},
      {:ex_doc, "~> 0.24", only: :dev, runtime: false},
      {:dialyxir, "~> 1.0", only: :dev, runtime: false},
      {:credo, "~> 1.6", only: [:dev, :test], runtime: false},
      {:yaml_elixir, "~> 2.8.0", only: [:test]}
    ]
  end

  defp package do
    [
      description: "Debug SPF records for any given mail domain",
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
