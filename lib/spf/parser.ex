defmodule Spf.Parser do
  @moduledoc """
  Functions to parse a list of tokens, given a context of ip, sender and domain


  """
  import Spf.Context

  # Helpers

  @spec pfxparse(binary) :: {:ok, Pfx.t()} | {:error, binary}
  defp pfxparse(pfx) do
    {:ok, Pfx.new(pfx)}
  rescue
    _ -> {:error, pfx}
  end

  defp rm_redirect(ctx) do
    case List.keytake(ctx[:ast], :redirect, 0) do
      nil ->
        ctx

      {redir, ast} ->
        log(ctx, :parse, :warn, "redirect #{inspect(redir)} ignored: `all` is present")
        |> Map.put(:ast, ast)
    end
  end

  defp cidr([]),
    do: [32, 128]

  defp cidr({:dual_cidr, [len4, len6], _}) do
    if len4 in 0..32 and len6 in 0..128,
      do: [len4, len6],
      else: :einvalid
  end

  def expand(ctx, []),
    do: ctx.domain

  def expand(_ctx, {:domspec, [:einvalid], _range}),
    do: :einvalid

  def expand(ctx, {toktype, tokens, _range}) when toktype in [:domspec, :exp_str] do
    for {token, args, _range} <- tokens do
      expand(ctx, token, args)
    end
    |> Enum.join()
  end

  # transformers:
  # 1. split on "." or the delimiters provided
  # 2. reversal if requested
  # 3. keep (max) N last elements if requested
  # 4. join with "."
  defp expand(ctx, :expand, [ltr, keep, reverse, delimiters]) do
    # result of expand1 token
    ctx.macro[ltr]
    |> String.split(delimiters)
    |> (fn x -> if reverse, do: Enum.reverse(x), else: x end).()
    |> (fn x -> if keep in 1..length(x), do: Enum.slice(x, -keep, keep), else: x end).()
    |> Enum.join(".")
  end

  defp expand(_ctx, :expand, [str]),
    # result of expand2 token
    do: str

  defp expand(_ctx, token_type, [str])
       when token_type in [:literal, :toplabel, :whitespace, :unknown],
       do: str

  # defp expand(_ctx, :literal, [str]),
  #   do: str

  defp taketok(args, toktype) do
    case List.keytake(args, toktype, 0) do
      nil -> {[], args}
      {token, args} -> {token, args}
    end
  end

  defp ast(ctx, {:exp, _tokval, range} = token) do
    # explain not added to ctx.ast but assigned to ctx.explain (only for the original SPF record)
    tokstr = String.slice(ctx.spf, range)

    if ctx.f_include do
      log(ctx, :parse, :info, "#{tokstr} - ignoring included explain")
    else
      if ctx.explain do
        log(ctx, :parse, :warn, "#{tokstr} - ignoring multiple explains")
      else
        Map.put(ctx, :explain, token)
      end
    end
  end

  defp ast(ctx, {_type, _tokval, _range} = token) do
    if ctx.f_all do
      log(ctx, :parse, :warn, "ignored #{inspect(token)}: term past `all`")
    else
      case token do
        {:all, _tokval, _range} ->
          Map.put(ctx, :f_all, true)
          |> Map.update(:ast, [token], fn tokens -> tokens ++ [token] end)
          |> rm_redirect()

        {:redirect, _tokval, _range} ->
          if ctx.f_redirect,
            do: log(ctx, :parse, :warn, "ignored: multiple redirects #{inspect(token)}"),
            else:
              Map.put(ctx, :f_redirect, true)
              |> Map.update(:ast, [token], fn tokens -> tokens ++ [token] end)

        _ ->
          Map.update(ctx, :ast, [token], fn tokens -> tokens ++ [token] end)
      end
    end
  end

  # Parse Context

  def parse(%{error: error} = ctx) when error != nil,
    do: ctx

  def parse(%{spf: spf} = ctx) do
    {:ok, tokens, rest, _, _, _} = Spf.tokenize(spf)

    ctx =
      Map.put(ctx, :spf, spf)
      |> Map.put(:spf_tokens, tokens)
      |> Map.put(:spf_rest, rest)
      |> Map.put(:ast, [])
      |> check(:spf_length)
      |> check(:spf_residue)

    Enum.reduce(tokens, ctx, &parse/2)
    |> check(:explain_reachable)
    |> check(:no_implicit)
  end

  # Parse Tokens

  # Version
  defp parse({:version, [n], _range} = token, ctx) do
    # TODO: DNS.grep checks for v=spf1, so we're always good here, no?
    # And if possibly not, then put in the syntax error
    case n do
      1 -> ctx
      _ -> log(ctx, :parse, :error, "unknown SPF version #{inspect(token)}")
    end
  end

  # Whitespace
  defp parse({:whitespace, [wspace], range} = _token, ctx) do
    ctx =
      if String.length(wspace) > 1,
        do: log(ctx, :parse, :warn, "repeated whitespace: #{inspect(range)}"),
        else: ctx

    if String.contains?(wspace, "\t"),
      do: log(ctx, :parse, :warn, "tab as whitespace: #{inspect(range)}"),
      else: ctx
  end

  # A, MX
  defp parse({atom, [qual, args], range}, ctx) when atom in [:a, :mx] do
    {spec, _} = taketok(args, :domspec)
    {dual, _} = taketok(args, :dual_cidr)

    domain = expand(ctx, spec)
    cidr = cidr(dual)

    if domain == :einvalid or cidr == :einvalid do
      Map.put(ctx, :error, :syntax_error)
      |> Map.put(:reason, "invalid term #{String.slice(ctx.spf, range)}")
      |> then(fn ctx -> log(ctx, :parse, :error, ctx.reason) end)
    else
      ast(ctx, {atom, [qual, domain, cidr], range})
      |> tick(:num_dnsm)
      |> log(:parse, :debug, "DNS MECH (#{ctx.num_dnsm}): #{String.slice(ctx.spf, range)}")
    end
  end

  # Ptr
  defp parse({:ptr, [qual, args], range} = _token, ctx) do
    {spec, _} = taketok(args, :domspec)

    ast(ctx, {:ptr, [qual, expand(ctx, spec)], range})
    |> tick(:num_dnsm)
    |> log(:parse, :debug, "DNS MECH (#{ctx.num_dnsm}): #{String.slice(ctx.spf, range)}")
    |> log(:parse, :warn, "ptr usage is not recommended")
  end

  # Include, Exists
  defp parse({atom, [qual, domspec], range}, ctx) when atom in [:include, :exists],
    do:
      ast(ctx, {atom, [qual, expand(ctx, domspec)], range})
      |> tick(:num_dnsm)
      |> log(:parse, :debug, "DNS MECH (#{ctx.num_dnsm}): #{String.slice(ctx.spf, range)}")

  # All
  defp parse({:all, [qual], range}, ctx),
    do: ast(ctx, {:all, [qual], range})

  # IP4, IP6
  defp parse({atom, [qual, ip], range}, ctx) when atom in [:ip4, :ip6] do
    case pfxparse(ip) do
      {:ok, pfx} ->
        ast(ctx, {atom, [qual, pfx], range})

      {:error, _} ->
        Map.put(ctx, :error, :syntax_error)
        |> Map.put(:reason, "syntax error for IP #{String.slice(ctx.spf, range)}")
        |> then(fn ctx -> log(ctx, :parse, :error, ctx.reason) end)
    end
  end

  # Redirect
  defp parse({:redirect, [domspec], range}, ctx),
    do:
      ast(ctx, {:redirect, [expand(ctx, domspec)], range})
      |> tick(:num_dnsm)
      |> log(:parse, :debug, "DNS MECH (#{ctx.num_dnsm}): #{String.slice(ctx.spf, range)}")

  # Exp - not included in count of dns mechanisms
  defp parse({:exp, [domspec], range}, ctx),
    do: ast(ctx, {:exp, [expand(ctx, domspec)], range})

  # Unknown_mod
  defp parse({:unknown_mod, _tokvalue, range} = _token, ctx) do
    # unknown_mod term may be ignored
    # like 'moo.cow-far_out=man:dog/cat'
    log(ctx, :parse, :warn, "ignored UNKNOWN MODIFIER \"#{String.slice(ctx.spf, range)}\"")
  end

  # Unknown
  defp parse({:unknown, _tokvalue, range} = _token, ctx) do
    log(ctx, :parse, :error, "UNKNOWN TERM \"#{String.slice(ctx.spf, range)}\"")
    |> Map.put(:error, :syntax_error)
    |> Map.put(:reason, "unknown term '#{String.slice(ctx.spf, range)}' at #{inspect(range)}")
  end

  # CatchAll
  defp parse(token, ctx),
    do: log(ctx, :parse, :error, "Spf.parser.check: no handler available for #{inspect(token)}")

  # Checks

  defp check(ctx, :spf_length) do
    case String.length(ctx.spf) do
      len when len > 512 -> log(ctx, :parse, :warn, "SPF string length #{len} > 512 characters")
      _ -> ctx
    end
  end

  defp check(ctx, :spf_residue) do
    case String.length(ctx.spf_rest) do
      len when len > 0 -> log(ctx, :parse, :warn, "SPF string residue #{inspect(ctx.spf_rest)}")
      _ -> ctx
    end
  end

  defp check(ctx, :explain_reachable) do
    # if none of the terms have a fail qualifier, an explain is superfluous
    if ctx.explain != nil do
      mechs =
        Enum.filter(ctx.ast, fn {type, _tokval, _range} -> type != :redirect end)
        |> Enum.map(fn {_type, tokval, _range} -> tokval end)
        |> Enum.filter(fn l -> List.first(l, ?+) == ?- end)

      case mechs do
        [] -> log(ctx, :parse, :warn, "SPF record cannot fail, so explain is never used")
        _ -> ctx
      end
    else
      ctx
    end
  end

  defp check(ctx, :no_implicit) do
    # warn if there's no redirect and no all present
    explicit = Enum.filter(ctx.ast, fn {type, _tokval, _range} -> type in [:all, :redirect] end)

    case explicit do
      [] -> log(ctx, :parse, :warn, "SPF record has implicit end (?all)")
      _ -> ctx
    end
  end
end
