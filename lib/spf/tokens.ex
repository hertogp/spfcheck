defmodule Spf.Tokens do
  @moduledoc """
  Combinators to turn an SPF string or an explain string into a list of `t:token/0`'s.

  This module provides two combinators:

  - `tokenize_spf/0`, which turns an SPF string into a list of tokens
  - `tokenize_exp/0`, which turns an explain string into tokens

  which are used by `Spf.Parser` for lexical analysis of an input string.

  The `start_token/6` and `token/6` are helper functions for internal use by
  `Spf.Tokens` that should've been private, but it seems they cannot be.

  """

  import NimbleParsec

  @m __MODULE__

  @type combinator :: NimbleParsec.t()

  @typedoc """
  qualifier = ?+ / ?- / ?~ / ??

  """
  @type q :: ?+ | ?- | ?~ | ??

  @typedoc """
  `range` denotes a token's `start..stop`-slice in the input string.

  """
  @type range :: Range.t()

  @typedoc """
  The token's `type`.

  There are several classes of tokens:
  - the version: `:version`,
  - a mechanism: `:a, :all, :exists, :exp, :include, :ip4, :ip6, :mx, :ptr`
  - a modifier: `:exp, :redirect`,
  - an explain string: `exp_str`,
  - an unknown modifier: `unknown_mod`,
  - an unknown token: `unknown`
  - whitespace: `:whitespace`,
  - a subtoken: `:domspec, :dual_cidr, :qualifier`, `:expand, :literal, :toplabel`

  Subtokens may appear as part of another token's value.

  `:exp_str` is produced by tokenizing the explain string.  After expanding the
  domain-spec of modifier `exp=domain-spec` into a domain name, that domain's
  TXT RR is retrieved and tokenized for later expansion into an explanation
  string.  This only happens when the SPF verdict is `:fail` and the `exp`
  modifier is present and has a valid domain name.

  The `:whitespace` token will match both spaces and tab characters in order to
  be able to warn about multiple spaces and/or tab characters being used.  Use
  of a tab character is technically a syntax error, but this library only warns
  about its use.

  The `:unknown` token is tried as a last resort and matches any non-space
  sequence.  When matched, it usually means the SPF string has a syntax error.

  """
  @type type ::
          :a
          | :all
          | :exists
          | :exp
          | :exp_str
          | :include
          | :ip4
          | :ip6
          | :mx
          | :ptr
          | :redirect
          | :unknown
          | :unknown_mod
          | :version
          | :whitespace
          | :exp_str
          # subtokens
          | :domspec
          | :dual_cidr
          | :qualifier
          | :expand
          | :literal
          | :toplabel

  @typedoc """
  A token represented as a tuple: `{type, list, range}`.

  Where:
  - `type` is an atom which denotes the token `t:type/0`
  - `list` may be empty or contain one or more values (including subtokens)
  - `range` is the `start..stop`-slice in the input string

  """
  @type token :: {type, list(), range}

  # Helpers

  @spec anycase(binary) :: combinator
  defp anycase(string) do
    # combinator that matches given `string`, case-insensitive.
    string
    |> String.to_charlist()
    |> Enum.map(&bothcases/1)
    |> Enum.reduce(empty(), fn elm, acc -> concat(acc, elm) end)
  end

  @spec bothcases(non_neg_integer) :: combinator
  defp bothcases(c) when ?a <= c and c <= ?z,
    do: ascii_char([c, c - 32])

  defp bothcases(c) when ?A <= c and c <= ?Z,
    do: ascii_char([c, c + 32])

  defp bothcases(c),
    do: ascii_char([c])

  @spec digit() :: combinator
  defp digit(),
    do: ascii_char([?0..?9])

  @spec alpha() :: combinator
  defp alpha(),
    do: ascii_char([?a..?z, ?A..?Z])

  @spec alphanum() :: combinator
  defp alphanum(),
    do: choice([alpha(), digit()])

  @spec dash_alphanum() :: combinator
  defp dash_alphanum(),
    do: times(string("-"), min: 1) |> concat(alphanum())

  @spec eoterm() :: combinator
  defp eoterm(),
    do: lookahead(choice([whitespace(), eos()]))

  @spec m_delimiter() :: combinator
  defp m_delimiter(),
    do: ascii_char([?., ?-, ?+, ?,, ?/, ?_, ?=])

  @spec m_letter() :: combinator
  defp m_letter(),
    do:
      ascii_char(
        [?s, ?l, ?o, ?d, ?i, ?p, ?h, ?c, ?r, ?t, ?v] ++
          [?S, ?L, ?O, ?D, ?I, ?P, ?H, ?C, ?R, ?T, ?V]
      )

  @spec m_literal() :: combinator
  defp m_literal(),
    # a single macro-literal character, unless we're looking at:
    # - a dual_cidr (which ends the term), or
    # - a toplabel
    do:
      lookahead_not(dual_cidr())
      |> lookahead_not(toplabel())
      |> ascii_char([0x21..0x24, 0x26..0x7E])

  @spec m_string() :: combinator
  defp m_string(),
    # notes:
    # - :toplabel is a special form of a :literal
    # - :toplabel matched separately in order to check :domspec's validity
    do: times(choice([expand(), toplabel(), literal()]), min: 1)

  @spec mod_name() :: combinator
  defp mod_name() do
    alpha()
    |> times(choice([alpha(), digit(), ascii_char([?-, ?_, ?.])]), min: 0)
  end

  @spec eoterm(combinator) :: combinator
  defp eoterm(c),
    do: concat(c, eoterm())

  @spec range(map, atom, non_neg_integer) :: range
  defp range(context, token_type, offset),
    # context should have a recorded start for label, if not, defaults to 0
    do: Range.new(Map.get(context, token_type, 0), offset - 1)

  # POST_TRAVERSE
  # TODO: howto make start_token() and token() private?

  @spec start(atom) :: combinator
  defp start(token_type) do
    # records current offset for given `token_type` in context
    empty()
    |> post_traverse({@m, :start_token, [token_type]})
  end

  @doc """
  Internal helper that records the start of a token of given `token_type`.

  This function must be called at the start of trying to lex a token of
  `token_type` and, when succesfull, the post_traverse function(s) can easily
  pickup the last recorded start for given `token_type`.

  """
  @spec start_token(binary, list, map, tuple, non_neg_integer, atom) :: {list, map}
  def start_token(_rest, args, context, _line, offset, token_type),
    do: {args, Map.put(context, token_type, offset)}

  @doc """
  Internal helper that turns a combinator result into a `t:token/0`.


  """
  @spec token(binary, list, map, tuple, non_neg_integer, atom) :: {[token], map}
  def token(rest, args, context, line, offset, atom)
  # line = {linenr, start_of_line}
  # offset = token_end
  # both token_end and start_of_line are (0-based offset from start of entire binary

  # Whitespace
  def token(_rest, args, context, _line, offset, :whitespace),
    do: {[{:whitespace, args, range(context, :whitespace, offset)}], context}

  # DualCidr
  def token(_rest, args, context, _line, offset, :dual_cidr2),
    do: {[{:dual_cidr, Enum.reverse(args), range(context, :dual_cidr2, offset)}], context}

  def token(_rest, args, context, _line, offset, :dual_cidr4),
    do: {[{:dual_cidr, args ++ [128], range(context, :dual_cidr4, offset)}], context}

  def token(_rest, args, context, _line, offset, :dual_cidr6),
    do: {[{:dual_cidr, [32] ++ args, range(context, :dual_cidr6, offset)}], context}

  # Version
  def token(_rest, args, context, _line, offset, :version),
    do: {[{:version, args, range(context, :version, offset)}], context}

  # Qualifier
  def token(_rest, args, context, _line, offset, :qualifier) do
    q = if args == [], do: ?+, else: hd(args)
    {[{:qualifier, q, range(context, :qualifier, offset)}], context}
  end

  # Include/Exists
  def token(_rest, args, context, _line, offset, atom) when atom in [:include, :exists] do
    [{:qualifier, q, _offset}, domspec] = Enum.reverse(args)
    {[{atom, [q, domspec], range(context, atom, offset)}], context}
  end

  # All
  def token(_rest, args, context, _line, offset, :all) do
    [{:qualifier, q, _offset}] = args
    {[{:all, [q], range(context, :all, offset)}], context}
  end

  # IP4/IP6
  def token(_rest, args, context, _line, offset, atom) when atom in [:ip4, :ip6] do
    # parser will check validity of address supplied
    [{:unknown, addr, _}, {:qualifier, q, _}] = args
    addr = List.to_string(addr)
    {[{atom, [q, addr], range(context, atom, offset)}], context}
  end

  # A/MX/PTR
  def token(_rest, args, context, _line, offset, atom) when atom in [:a, :mx, :ptr] do
    tokval =
      case Enum.reverse(args) do
        [{:qualifier, q, _range}] -> [q, []]
        [{:qualifier, q, _rang} | args] -> [q, args]
      end

    {[{atom, tokval, range(context, atom, offset)}], context}
  end

  # Literal
  def token(_rest, args, context, _line, offset, :literal),
    do: {[{:literal, args, range(context, :literal, offset)}], context}

  # Transform
  def token(_rest, args, context, _line, _offset, :transform) do
    # *DIGIT ( "r" / "R") <- keep, reverse: is optional in a transform
    # - keep == 0, means keep all
    tokval =
      case args do
        [] -> [0, false]
        [?r] -> [0, true]
        [?R] -> [0, true]
        [?r | tail] -> [Enum.reverse(tail) |> List.to_integer(), true]
        [?R | tail] -> [Enum.reverse(tail) |> List.to_integer(), true]
        num -> [Enum.reverse(num) |> List.to_integer(), false]
      end

    {tokval, context}
  end

  # Toplabel
  def token(_rest, args, context, _line, offset, :toplabel),
    do: {[{:toplabel, args, range(context, :toplabel, offset)}], context}

  # Expand
  def token(_rest, args, context, _line, offset, :expand1) do
    [ltr, reverse, keep | delims] = Enum.reverse(args)
    delims = if delims == [], do: ["."], else: Enum.map(delims, fn x -> List.to_string([x]) end)
    tokval = [ltr, keep, reverse, delims]

    {[{:expand, tokval, range(context, :expand1, offset)}], context}
  end

  def token(_rest, args, context, _line, offset, :expand2),
    do: {[{:expand, args, range(context, :expand2, offset)}], context}

  # Domspec
  def token(_rest, args, context, _line, offset, :domspec) when length(args) == 0,
    do: {[{:domspec, args, range(context, :domspec, offset)}], context}

  def token(_rest, args, context, _line, offset, :domspec) do
    # A legal domspec:
    # - MUST end in an :expand macro or a :toplabel, and
    # - MUST NOT have macroletters ?c, ?r, ?t
    letters = for {token, args, _} <- args, token == :expand, do: List.first(args)
    lasttok = List.first(args) |> elem(0)

    invalid =
      ?c in letters or ?r in letters or ?t in letters or lasttok not in [:expand, :toplabel]

    args = if invalid, do: [:einvalid], else: Enum.reverse(args)

    {[{:domspec, args, range(context, :domspec, offset)}], context}
  end

  # Redirect
  def token(_rest, args, context, _line, offset, :redirect),
    do: {[{:redirect, Enum.reverse(args), range(context, :redirect, offset)}], context}

  # Unknown_mod
  def token(_rest, args, context, _line, offset, :unknown_mod),
    do: {[{:unknown_mod, Enum.reverse(args), range(context, :unknown_mod, offset)}], context}

  # Unknown
  def token(_rest, args, context, _line, offset, :unknown),
    do: {[{:unknown, Enum.reverse(args), range(context, :unknown, offset)}], context}

  # Exp_str
  def token(rest, args, context, _line, offset, :exp_str) do
    if String.length(rest) > 0 do
      {[{:exp_str, [], range(context, :exp_str, offset)}], context}
    else
      {[{:exp_str, Enum.reverse(args), range(context, :exp_str, offset)}], context}
    end
  end

  # CatchAll
  def token(_rest, args, context, _line, offset, atom),
    do: {[{atom, Enum.reverse(args), range(context, atom, offset)}], context}

  # COMBINATORS

  @spec qualifier() :: combinator
  defp qualifier() do
    # {:qualifier, [q], range}
    # when used, this combinator always produces a token where `q` defaults to `?+`.
    start(:qualifier)
    |> optional(ascii_char([?+, ?-, ?~, ??]))
    |> post_traverse({@m, :token, [:qualifier]})
  end

  defp qualifier(combinator),
    do: concat(combinator, qualifier())

  @spec spf_term() :: combinator
  defp spf_term() do
    # note: unknown() must be last.
    choice([
      whitespace(),
      version(),
      all(),
      a(),
      mx(),
      ip4(),
      ip6(),
      include(),
      exists(),
      ptr(),
      redirect(),
      exp(),
      unknown_mod(),
      unknown()
    ])
  end

  # TOKENS

  @spec a() :: combinator
  defp a() do
    # {:a, [q, [token]], range}
    start(:a)
    |> qualifier()
    |> ignore(anycase("a"))
    |> optional(domspec(":"))
    |> optional(dual_cidr())
    |> eoterm()
    |> post_traverse({@m, :token, [:a]})
  end

  @spec all() :: combinator
  defp all() do
    # {:all, [q], range]}
    start(:all)
    |> qualifier()
    |> ignore(anycase("all"))
    |> eoterm()
    |> post_traverse({@m, :token, [:all]})
  end

  @spec exists() :: combinator
  defp exists() do
    # {:exists, [q, domspec], range}
    start(:exists)
    |> qualifier()
    |> ignore(anycase("exists"))
    |> concat(domspec(":"))
    |> eoterm()
    |> post_traverse({@m, :token, [:exists]})
  end

  @spec exp() :: combinator
  defp exp() do
    # {:exp, [domspec], range}
    start(:exp)
    |> ignore(anycase("exp"))
    |> concat(domspec("="))
    |> eoterm()
    |> post_traverse({@m, :token, [:exp]})
  end

  @spec include() :: combinator
  defp include() do
    # {:include, [q, domspec], range}
    start(:include)
    |> qualifier()
    |> ignore(anycase("include"))
    |> concat(domspec(":"))
    |> eoterm()
    |> post_traverse({@m, :token, [:include]})
  end

  @spec ip4() :: combinator
  defp ip4() do
    # {:ip4, [q, address], range}
    start(:ip4)
    |> qualifier()
    |> ignore(anycase("ip4:"))
    |> unknown()
    |> post_traverse({@m, :token, [:ip4]})
  end

  @spec ip6() :: combinator
  defp ip6() do
    # {:ip6, [q, address], range}
    start(:ip6)
    |> qualifier()
    |> ignore(anycase("ip6:"))
    |> unknown()
    |> post_traverse({@m, :token, [:ip6]})
  end

  @spec mx() :: combinator
  defp mx() do
    # {:mx, [q, [token]], range}
    start(:mx)
    |> qualifier()
    |> ignore(anycase("mx"))
    |> optional(domspec(":"))
    |> optional(dual_cidr())
    |> eoterm()
    |> post_traverse({@m, :token, [:mx]})
  end

  @spec ptr() :: combinator
  defp ptr() do
    # {:ptr, [q, domspec], range}
    start(:ptr)
    |> qualifier()
    |> ignore(anycase("ptr"))
    |> optional(domspec(":"))
    |> eoterm()
    |> post_traverse({@m, :token, [:ptr]})
  end

  @spec version() :: combinator
  defp version() do
    # {:version, [v], range}
    start(:version)
    |> ignore(anycase("v=spf"))
    |> integer(min: 1)
    |> eoterm()
    |> post_traverse({@m, :token, [:version]})
  end

  @spec redirect() :: combinator
  defp redirect() do
    # {:redirect, [domspec], range}
    start(:redirect)
    |> ignore(anycase("redirect"))
    |> concat(domspec("="))
    |> eoterm()
    |> post_traverse({@m, :token, [:redirect]})
  end

  # SUBTOKENS

  @spec domspec() :: combinator
  defp domspec() do
    # {:domspec, [token], range}
    # - tokens include: :toplabel, :expand, :literal
    # - higher level tokens need to use domspec/1
    start(:domspec)
    |> concat(m_string())
    |> post_traverse({@m, :token, [:domspec]})
  end

  @spec domspec(binary) :: combinator
  defp domspec(str) do
    # match a domspec after ignoring string `str` (i.e. ":" or "=")
    ignore(string(str))
    |> concat(domspec())
  end

  @spec dual_cidr() :: combinator
  defp dual_cidr() do
    # {:dual_cidr, [len4, len6], range}
    # - happily match anything for address and all numbers for length
    #   since parser will do additional checks
    choice([
      start(:dual_cidr2)
      |> ignore(string("/"))
      |> integer(min: 1)
      |> ignore(string("//"))
      |> integer(min: 1)
      |> eoterm()
      |> post_traverse({@m, :token, [:dual_cidr2]}),
      start(:dual_cidr4)
      |> ignore(string("/"))
      |> integer(min: 1)
      |> eoterm()
      |> post_traverse({@m, :token, [:dual_cidr4]}),
      start(:dual_cidr6)
      |> ignore(string("//"))
      |> integer(min: 1)
      |> eoterm()
      |> post_traverse({@m, :token, [:dual_cidr6]})
    ])
  end

  @spec unknown_mod() :: combinator
  defp unknown_mod() do
    # {:unknown_mod, [name, [token]], range}
    start(:unknown_mod)
    |> concat(mod_name())
    |> ignore(string("="))
    |> reduce({List, :to_string, []})
    |> concat(m_string())
    |> eoterm()
    |> post_traverse({@m, :token, [:unknown_mod]})
  end

  @spec unknown() :: combinator
  defp unknown() do
    # {:unknown, [string], range}
    start(:unknown)
    |> times(ascii_char(not: ?\ , not: ?\t), min: 1)
    |> post_traverse({@m, :token, [:unknown]})
  end

  @spec unknown(combinator) :: combinator
  defp unknown(combinator),
    do: concat(combinator, unknown())

  @spec whitespace() :: combinator
  defp whitespace() do
    # {:whitespace, [string], range}
    # - also accepts tabs (technically a syntax error) for warning
    start(:whitespace)
    |> times(ascii_char([?\ , ?\t]), min: 1)
    |> reduce({List, :to_string, []})
    |> post_traverse({@m, :token, [:whitespace]})
  end

  # L2 TOKENS

  @spec expand() :: combinator
  defp expand() do
    # {:expand, list, range}
    choice([
      expand1(),
      expand2()
    ])
  end

  @spec expand1() :: combinator
  defp expand1() do
    # {:expand1, [letter, keep, reverse, [delim]], range}
    start(:expand1)
    |> ignore(string("%{"))
    |> concat(m_letter())
    |> m_transform()
    |> repeat(m_delimiter())
    |> ignore(string("}"))
    |> post_traverse({@m, :token, [:expand1]})
  end

  @spec expand2() :: combinator
  defp expand2() do
    # {:expand2, [string], range}
    start(:expand2)
    |> ignore(ascii_char([?%]))
    |> ascii_char([?%, ?-, ?_])
    |> reduce({List, :to_string, []})
    |> post_traverse({@m, :token, [:expand2]})
  end

  @spec literal() :: combinator
  defp literal() do
    # {:literal, [binary], range}
    # notes:
    # - will not match literals part of toplabel or dual_cidr (!)
    # - so macro-string = times(choice([dual_cidr, toplabel, literal]), min: 1)
    start(:literal)
    |> times(m_literal(), min: 1)
    |> reduce({List, :to_string, []})
    |> post_traverse({@m, :token, [:literal]})
  end

  @spec m_transform() :: combinator
  defp m_transform() do
    # a domspec-expand without a transform will have a :transform token with
    # an empty list as token value
    times(digit(), min: 0)
    |> optional(ascii_char([?r, ?R]))
    |> post_traverse({@m, :token, [:transform]})
  end

  @spec m_transform(combinator) :: combinator
  defp m_transform(combinator),
    do: concat(combinator, m_transform())

  @spec toplabel() :: combinator
  defp toplabel() do
    # {:toplabel, [string], range}
    # - ignore trailing dot, all domains are relative to root
    start(:toplabel)
    |> string(".")
    |> choice([ldhlabel1(), ldhlabel2()])
    |> optional(ignore(string(".")))
    |> choice([eoterm(), lookahead(dual_cidr())])
    |> reduce({List, :to_string, []})
    |> post_traverse({@m, :token, [:toplabel]})
  end

  @spec ldhlabel1() :: combinator
  defp ldhlabel1() do
    # start with alpha
    alpha()
    |> times(choice([dash_alphanum(), alphanum()]), min: 0)
  end

  @spec ldhlabel2() :: combinator
  defp ldhlabel2() do
    # starts with digit
    times(digit(), min: 1)
    |> choice([dash_alphanum(), alpha()])
    |> times(choice([dash_alphanum(), alphanum()]), min: 0)
  end

  # API

  @doc """
  Token `{:exp_str, [token], range}`.

  Where `token`'s include: `:expand`, `:toplabel`, `:literal` or `:whitespace`.

  After expanding the domain spec, of an `:exp`-token into a domain name, its
  TXT RR is retrieved.  That RR's text value is called the explain-string.
  This string is the only place where macro-letters `c`, `r`, or `t` are
  allowed.

  The list of tokens can then be expanded into the final explanation by the parser.

  """
  @spec tokenize_exp() :: combinator
  def tokenize_exp() do
    start(:exp_str)
    |> times(choice([m_string(), whitespace()]), min: 1)
    |> post_traverse({@m, :token, [:exp_str]})
  end

  @doc """
  Combinator that creates a list of tokens for the SPF terms found in an input string.
  """
  @spec tokenize_spf() :: combinator
  def tokenize_spf(),
    do: spf_term() |> repeat()
end
