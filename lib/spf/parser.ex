defmodule Spf.Parser do
  @moduledoc """
  Functions to parse a list of tokens, given a context of ip, sender and domain
  """

  # Helpers

  # -> TODO, remove once Pfx.parse becomes available
  defp pfxparse(pfx) do
    {:ok, Pfx.new(pfx)}
  rescue
    _ -> {:error, pfx}
  end

  defp log(ctx, type, str) do
    IO.puts(:stderr, "[#{type}] #{str}")
    Map.update(ctx, :msg, [{type, str}], fn msgs -> [{type, str} | msgs] end)
  end

  defp rm_redirect(ctx) do
    case List.keytake(ctx[:ast], :redirect, 0) do
      nil ->
        ctx

      {redir, ast} ->
        log(ctx, :warn, "since `all` is present, ignoring: #{inspect(redir)}")
        |> Map.put(:ast, ast)
    end
  end

  # either append or ignore new token
  defp ast(ctx, token) do
    if ctx[:flags][:all] do
      log(ctx, :warn, "term after `all`, ignoring: #{inspect(token)}")
    else
      case token do
        {:all, _tokval, _offset} ->
          put_in(ctx, [Access.key(:flags, %{}), Access.key(:all)], true)
          |> Map.update(:ast, [token], fn tokens -> tokens ++ [token] end)
          |> rm_redirect()

        {:redirect, _tokval, _offset} ->
          if ctx[:flags][:redirect],
            do: log(ctx, :warn, "multiple redirects, ignoring: #{inspect(token)}"),
            else:
              put_in(ctx, [Access.key(:flags, %{}), Access.key(:redirect)], true)
              |> Map.update(:ast, [token], fn tokens -> tokens ++ [token] end)

        _ ->
          Map.update(ctx, :ast, [token], fn tokens -> tokens ++ [token] end)
      end
    end
  end

  # Parser

  def parse(ctx = %{error: reason}) do
    verdict =
      case reason do
        :nxdomain -> "none"
        _ -> "temperror"
      end

    log(ctx, :error, "#{ctx.domain} #{inspect(reason)}")
    |> Map.put(:verdict, verdict)
  end

  def parse(ctx = %{spf: []}) do
    log(ctx, :note, "no spf records found")
    |> Map.put(:verdict, "none")
  end

  def parse(ctx = %{spf: [spf]}) do
    len = String.length(spf)

    ctx =
      Map.put(ctx, :spf, spf)
      |> Map.put(:ast, [])

    ctx =
      if len > 512,
        do: log(ctx, :warn, "spf record length: #{len} exceeds recommended length of 512"),
        else: ctx

    Spf.tokenize(spf)
    |> parsep(ctx)
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

  # Implementation

  defp parsep({:ok, tokens, rest, _, _, _}, ctx) do
    # TODO:
    # - move warning to post parser checks
    #   if String.length(rest) > 0,
    #     do: log(ctx, :warn, "residual spf text: '#{rest}'"),
    #     else: ctx

    ctx =
      Map.put(ctx, :spf_tokens, tokens)
      |> Map.put(:spf_rest, rest)

    Enum.reduce(tokens, ctx, &execp/2)
  end

  defp execp({token, args, range} = tok, ctx) do
    apply(__MODULE__, token, [ctx, range] ++ args)
  rescue
    err ->
      log(ctx, :error, "token `:#{token}` -> #{inspect(err)}")
      |> ast(tok)
  end

  def version(ctx, slice, n) do
    if n != 1,
      do:
        log(ctx, :error, "unknown SPF version (#{n}): #{inspect(String.slice(ctx[:spf], slice))}"),
      else: ctx
  end

  # whitespace is ignored but may yield a warning
  def whitespace(ctx, offset, wspace) do
    ctx =
      if String.length(wspace) > 1,
        do: log(ctx, :warn, "col #{offset}: repeated whitespace"),
        else: ctx

    if String.contains?(wspace, "\t"),
      do: log(ctx, :warn, "col #{offset}: whitespace contains tab"),
      else: ctx
  end

  defp cidr(nil),
    do: [32, 128]

  defp cidr({:dual_cidr, args, _}),
    do: args

  defp domain(ctx, nil),
    do: ctx[:domain]

  defp domain(ctx, {:domain_spec, tokens, _offset}) do
    for {token, args, _offset} <- tokens do
      IO.inspect(token, label: :mexec_token)
      mexec(ctx, token, args)
    end
    |> Enum.join()
  end

  # transformers:
  # 1. split on "." or the delimiters provided
  # 2. reversal if requested
  # 3. keep (max) N last elements if requested
  # 4. join with "."
  defp mexec(ctx, :expand, [ltr, keep, reverse, delimiters]) do
    ctx[:macro][ltr]
    |> String.split(delimiters)
    |> (fn x -> if reverse, do: Enum.reverse(x), else: x end).()
    |> (fn x -> if keep in 1..length(x), do: Enum.slice(x, -keep, keep), else: x end).()
    |> Enum.join(".")
  end

  defp mexec(_ctx, :literal, str),
    do: str

  # MECHANISMS

  defp taketok(args, token) do
    case List.keytake(args, token, 0) do
      nil -> {nil, args}
      {tok, args} -> {tok, args}
    end
  end

  def a(ctx, offset, qual, args \\ []) do
    {spec, _} = taketok(args, :domain_spec)
    {dual, _} = taketok(args, :dual_cidr)
    # TODO: may be check args length is <= 2?
    ast(ctx, {:a, [qual, domain(ctx, spec), cidr(dual)], offset})
  end

  def mx(ctx, offset, qual, args \\ []) do
    {spec, _} = taketok(args, :domain_spec)
    {dual, _} = taketok(args, :dual_cidr)
    ast(ctx, {:mx, [qual, domain(ctx, spec), cidr(dual)], offset})
  end

  def include(ctx, offset, qual, domain_spec) do
    ast(ctx, {:include, [qual, domain(ctx, domain_spec)], offset})
  end

  def exists(ctx, offset, qual, domain_spec) do
    ast(ctx, {:exists, [qual, domain(ctx, domain_spec)], offset})
  end

  def all(ctx, offset, qual) do
    ast(ctx, {:all, [qual], offset})
  end

  def ptr(ctx, offset, qual, args \\ []) do
    domain_spec = if args == [], do: nil, else: hd(args)
    ast(ctx, {:ptr, [qual, domain(ctx, domain_spec)], offset})
  end

  def ip4(ctx, range, qual, ip) do
    case pfxparse(ip) do
      {:ok, pfx} ->
        ast(ctx, {:ip4, [qual, pfx], range})

      {:error, _} ->
        log(ctx, :warn, "ignoring invalid mechanism: '#{String.slice(ctx[:spf], range)}'")
    end
  end

  def ip6(ctx, range, qual, ip) do
    case pfxparse(ip) do
      {:ok, pfx} ->
        ast(ctx, {:ip6, [qual, pfx], range})

      {:error, _} ->
        log(ctx, :warn, "ignoring invalid mechanism: '#{String.slice(ctx[:spf], range)}'")
    end
  end

  # Modifiers
  def redirect(ctx, range, domain_spec),
    do: ast(ctx, {:redirect, [domain(ctx, domain_spec)], range})

  def exp(ctx, range, domain_spec),
    do: ast(ctx, {:exp, [domain(ctx, domain_spec)], range})
end
