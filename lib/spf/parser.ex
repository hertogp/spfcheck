defmodule Spf.Parser do
  @moduledoc """
  Functions to parse a list of tokens, given a context of ip, sender and domain
  """

  import Spf.Utils
  # Helpers

  # -> TODO, remove once Pfx.parse becomes available
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
        log(ctx, :warn, redir, "ignored:  `all` is present")
        |> Map.put(:ast, ast)
    end
  end

  defp cidr(nil),
    do: [32, 128]

  defp cidr({:dual_cidr, args, _}),
    do: args

  defp domain(ctx, nil),
    do: ctx[:domain]

  defp domain(ctx, {:domain_spec, tokens, _range}) do
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
    ctx[:macro][ltr]
    |> String.split(delimiters)
    |> (fn x -> if reverse, do: Enum.reverse(x), else: x end).()
    |> (fn x -> if keep in 1..length(x), do: Enum.slice(x, -keep, keep), else: x end).()
    |> Enum.join(".")
  end

  defp expand(_ctx, :literal, str),
    do: str

  defp taketok(args, token) do
    case List.keytake(args, token, 0) do
      nil -> {nil, args}
      {tok, args} -> {tok, args}
    end
  end

  # either append or ignore new token
  defp ast(ctx, {:exp, _, _} = token) do
    if ctx[:nth] > 0 do
      log(ctx, :info, token, "ignored: is #{ctx[:nth]}-th spf's explain")
    else
      if ctx[:exp] do
        log(ctx, :info, token, "ignored: multiple explains")
      else
        Map.put(ctx, :exp, token)
      end
    end
  end

  defp ast(ctx, token) do
    if ctx[:flags][:all] do
      log(ctx, :warn, token, "ignored: term past `all`")
    else
      case token do
        {:all, _tokval, _range} ->
          put_in(ctx, [Access.key(:flags, %{}), Access.key(:all)], true)
          |> Map.update(:ast, [token], fn tokens -> tokens ++ [token] end)
          |> rm_redirect()

        {:redirect, _tokval, _range} ->
          if ctx[:flags][:redirect],
            do: log(ctx, :warn, token, "ignored: multiple redirects"),
            else:
              put_in(ctx, [Access.key(:flags, %{}), Access.key(:redirect)], true)
              |> Map.update(:ast, [token], fn tokens -> tokens ++ [token] end)

        _ ->
          Map.update(ctx, :ast, [token], fn tokens -> tokens ++ [token] end)
      end
    end
  end

  # Parser

  def parse(%{error: reason} = ctx) do
    verdict =
      case reason do
        :nxdomain -> "none"
        _ -> "temperror"
      end

    log(ctx, :error, "#{ctx.domain} #{inspect(reason)}")
    |> Map.put(:verdict, verdict)
  end

  def parse(%{spf: []} = ctx) do
    log(ctx, :note, "no spf records found")
    |> Map.put(:verdict, "none")
  end

  def parse(%{spf: [spf]} = ctx) do
    {:ok, tokens, rest, _, _, _} = Spf.tokenize(spf)

    ctx =
      Map.put(ctx, :spf, spf)
      |> Map.put(:spf_tokens, tokens)
      |> Map.put(:spf_rest, rest)
      |> Map.put(:ast, [])

    len = String.length(spf)

    ctx =
      if len > 512,
        do: log(ctx, :warn, "spf record length: #{len} exceeds recommended length of 512"),
        else: ctx

    ctx =
      if String.length(rest) > 0,
        do: log(ctx, :DEBUG, "SPF string residue found: #{rest}"),
        else: ctx

    Enum.reduce(tokens, ctx, &check/2)
  end

  def parse(ctx = %{spf: spf}) do
    log(ctx, :error, "#{length(spf)} spf records found")
    |> Map.put(:spf, spf)
    |> Map.put(:verdict, "permerror")
  end

  # Checks
  # TODO: implement a number of checks
  # - dns name checks (4.3) (both initially and for expanded names)
  # --4.4 txt record lookup, timeout or RCODE not in [0, 3] -> temperror
  # - 4.5 spf record selection: starts with 'v=spf1'
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
  #   - filter names, keep eqal to <target> domain or subdomain thereof
  #   - 1+ name remains -> match, if empty -> no-match

  # Check Tokens

  # Version
  defp check({:version, [n], _range} = token, ctx) do
    case n do
      1 -> ctx
      _ -> log(ctx, :error, token, "unknown SPF version")
    end
  end

  # Whitespace
  defp check({:whitespace, [wspace], _range} = token, ctx) do
    ctx =
      if String.length(wspace) > 1,
        do: log(ctx, :warn, token, "repeated whitespace"),
        else: ctx

    if String.contains?(wspace, "\t"),
      do: log(ctx, :warn, token, "whitespace contains tab"),
      else: ctx
  end

  # A, MX
  defp check({atom, [qual, args], range}, ctx) when atom in [:a, :mx] do
    {spec, _} = taketok(args, :domain_spec)
    {dual, _} = taketok(args, :dual_cidr)

    ast(ctx, {atom, [qual, domain(ctx, spec), cidr(dual)], range})
    |> tick(:num_dnsm)
  end

  # Include, Exists
  defp check({atom, [qual, domain_spec], range}, ctx) when atom in [:include, :exists],
    do: ast(ctx, {atom, [qual, domain(ctx, domain_spec)], range}) |> tick(:num_dnsm)

  # All
  defp check({:all, [qual], range}, ctx),
    do: ast(ctx, {:all, [qual], range})

  # Ptr
  defp check({:ptr, [qual | args], range}, ctx) do
    domain_spec = if args == [], do: nil, else: hd(args)

    ast(ctx, {:ptr, [qual, domain(ctx, domain_spec)], range})
    |> tick(:num_dnsm)
  end

  # IP4, IP6
  defp check({atom, [qual, ip], range} = token, ctx) when atom in [:ip4, :ip6] do
    case pfxparse(ip) do
      {:ok, pfx} -> ast(ctx, {atom, [qual, pfx], range})
      {:error, _} -> log(ctx, :warn, token, "ignoring invalid IP")
    end
  end

  # Redirect, Exp
  defp check({:redirect, [domain_spec], range}, ctx),
    do: ast(ctx, {:redirect, [domain(ctx, domain_spec)], range}) |> tick(:num_dnsm)

  # Exp - not included in count of dns mechanisms
  defp check({:exp, [domain_spec], range}, ctx),
    do: ast(ctx, {:exp, [domain(ctx, domain_spec)], range})

  # CatchAll
  defp check(token, ctx),
    do: log(ctx, :DEBUG, token, "no handler available")
end
