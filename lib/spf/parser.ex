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

  defp cidr({:dual_cidr, args, _}),
    do: args

  def domain(ctx, []),
    do: ctx.domain

  def domain(ctx, {:domain_spec, tokens, _range}) do
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
    ctx.macro[ltr]
    |> String.split(delimiters)
    |> (fn x -> if reverse, do: Enum.reverse(x), else: x end).()
    |> (fn x -> if keep in 1..length(x), do: Enum.slice(x, -keep, keep), else: x end).()
    |> Enum.join(".")
  end

  defp expand(_ctx, :literal, [str]),
    do: str

  defp taketok(args, toktype) do
    case List.keytake(args, toktype, 0) do
      nil -> {[], args}
      {token, args} -> {token, args}
    end
  end

  defp ast(ctx, {:exp, _tokval, range} = token) do
    # eplain not added to ctx.ast but only for the original SPF record
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

  # Parser

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

  # Checks
  # TODO: implement a number of checks
  # - 4.6 spf syntax is checked -> any error yields a permerror
  # - 4.6.1 eval mechanisms left to right (default is implicit ?all = neutral)
  # - 4.6.2 if mech matches, its qual is the result of the spf record
  # - 4.6.3 `redirect` is evaluated after all mechanism have been exhausted
  # - 4.6.4 spf eval overall limit of DNS mech/modifiers is 10:
  #   -> a, mx, ptr, include, exists and redirect
  #   + mx  -> num of mx names to resolve is included in the 10 limit
  #         -> max 10 mx names may be resolved, the 11-th causes a permerror
  #   + ptr -> num of ptr names resolved is included in the 10 limit
  #         -> max 10 names may be resolved, the others are ignored (!)
  #   + void lookups (nxdomain or 0 answers) SHOULD be max 2, exceed -> permerror
  #         -> RCODE 0 with no answers, or RCODE 3 (nxdomain)
  # - 4.7 no matches and no redirect -> default result is `?all`, ie neutral
  # - 4.8 no domain-spec provided -> use <domain> of check_host() call
  #         -> SPF result for invalid domains is unspecified
  #         -> so simply warn, ignore and move on
  # - 5.1 all
  #   - mechs after all are ignored
  #   - if all is present, redirect is ignored (regardless of ordering)
  # - 5.5 ptr
  #   - warn that its use is NOT recommended
  #   - reverse lookup -> name(s) -> ip(s) (lookup all names)
  #   - PTR RR lookup fails -> ptr fails to match
  #   - A RR lookup fails -> name is skipped, continue with the others
  #   - collect validated names (lookup name -> ip is <ip>, then name is validated)
  #   - filter names, keep those equal to <target> domain or subdomain thereof
  #   - 1+ name remains -> match, if empty -> no-match

  # Parse Tokens

  # Version
  defp parse({:version, [n], _range} = token, ctx) do
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
    {spec, _} = taketok(args, :domain_spec)
    {dual, _} = taketok(args, :dual_cidr)

    ast(ctx, {atom, [qual, domain(ctx, spec), cidr(dual)], range})
    |> tick(:num_dnsm)
    |> log(:parse, :debug, "DNS MECH (#{ctx.num_dnsm}): #{String.slice(ctx.spf, range)}")
  end

  # Ptr
  defp parse({:ptr, [qual, args], range} = _token, ctx) do
    {spec, _} = taketok(args, :domain_spec)

    ast(ctx, {:ptr, [qual, domain(ctx, spec)], range})
    |> tick(:num_dnsm)
    |> log(:parse, :debug, "DNS MECH (#{ctx.num_dnsm}): #{String.slice(ctx.spf, range)}")
    |> log(:parse, :warn, "ptr usage is not recommended")
  end

  # Include, Exists
  defp parse({atom, [qual, domain_spec], range}, ctx) when atom in [:include, :exists],
    do:
      ast(ctx, {atom, [qual, domain(ctx, domain_spec)], range})
      |> tick(:num_dnsm)
      |> log(:parse, :debug, "DNS MECH (#{ctx.num_dnsm}): #{String.slice(ctx.spf, range)}")

  # All
  defp parse({:all, [qual], range}, ctx),
    do: ast(ctx, {:all, [qual], range})

  # IP4, IP6
  defp parse({atom, [qual, ip], range} = token, ctx) when atom in [:ip4, :ip6] do
    case pfxparse(ip) do
      {:ok, pfx} -> ast(ctx, {atom, [qual, pfx], range})
      {:error, _} -> log(ctx, :parse, :warn, "ignoring invalid IP in #{inspect(token)}")
    end
  end

  # Redirect
  defp parse({:redirect, [domain_spec], range}, ctx),
    do:
      ast(ctx, {:redirect, [domain(ctx, domain_spec)], range})
      |> tick(:num_dnsm)
      |> log(:parse, :debug, "DNS MECH (#{ctx.num_dnsm}): #{String.slice(ctx.spf, range)}")

  # Exp - not included in count of dns mechanisms
  defp parse({:exp, [domain_spec], range}, ctx),
    do: ast(ctx, {:exp, [domain(ctx, domain_spec)], range})

  defp parse({:unknown, _tokvalue, range} = _token, ctx),
    do: log(ctx, :parse, :error, "UNKNOWN TERM \"#{String.slice(ctx.spf, range)}\"")

  # CatchAll
  defp parse(token, ctx),
    do: log(ctx, :parse, :error, "Spf.parser.check: no handler available for #{inspect(token)}")

  # Checks for ast and spf
  # Spf_length
  defp check(ctx, :spf_length) do
    case String.length(ctx.spf) do
      len when len > 512 -> log(ctx, :parse, :warn, "SPF string length #{len} > 512 characters")
      _ -> ctx
    end
  end

  # Spf_residue
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
