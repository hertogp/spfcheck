defmodule Spf.Tokens do
  @moduledoc """
  Combinators and functions to tokenize an SPF string or an explain string.

  Tokens are represented by `{type, value, range}`-tuples. The token types
  include:

  - [`:version`](`version/0`)
  - [`:whitespace`](`whitespace/0`)
  - [`:a`](`a/0`)
  - [`:mx`](`mx/0`)
  - [`:include`](`include/0`)
  - [`:exists`](`exists/0`)
  - [`:ip4`](`ip4/0`)
  - [`:ip6`](`ip6/0`)
  - [`:ptr`](`ptr/0`)
  - [`redirect`](`redirect/0`)
  - [`:all`](`all/0`)
  - [`:exp`](`exp/0`)
  - [`:unknown_mod`](`unknown_mod/0`)
  - [`:unknown`](`unknown/0`)

  and sub-tokens that may appear in token values:

  - [`:dual_cidr`](`dual_cidr/0`)
  - [`:domspec`](`domspec/0`)
      - [`:expand`](`expand/0`)
      - [`:literal`](`literal/0`)
      - [`:toplabel`](`toplabel/0`)

  """

  import NimbleParsec

  @typedoc """
  qualifier = ?+ / ?- / ?~ / ??
  """
  @type q :: ?+ | ?- | ?~ | ??

  @typedoc """
  The range (`start..stop//step)` of a token in the input string.

  """
  @type range :: Range.t()

  @type t :: NimbleParsec.t()

  @typedoc """
  A token represented as a tuple: {type, value, range}.

  The `value` is a list of either strings, number(s) or intermediary tokens.

  """
  @type token :: {atom, list(), range}

  @m __MODULE__

  # Helpers

  @spec anycase(binary) :: t
  defp anycase(string) do
    # combinator that matches given `string`, case-insensitive.
    string
    |> String.to_charlist()
    |> Enum.map(&bothcases/1)
    |> Enum.reduce(empty(), fn elm, acc -> concat(acc, elm) end)
  end

  @spec bothcases(char) :: t
  defp bothcases(c) when ?a <= c and c <= ?z,
    do: ascii_char([c, c - 32])

  defp bothcases(c) when ?A <= c and c <= ?Z,
    do: ascii_char([c, c + 32])

  defp bothcases(c),
    do: ascii_char([c])

  defp digit(),
    do: ascii_char([?0..?9])

  defp alpha(),
    do: ascii_char([?a..?z, ?A..?Z])

  defp alphanum(),
    do: choice([alpha(), digit()])

  defp dash_alphanum(),
    do: times(string("-"), min: 1) |> concat(alphanum())

  defp eoterm(),
    do: lookahead(choice([whitespace(), eos()]))

  defp eoterm(c),
    do: concat(c, eoterm())

  defp range(context, label, offset),
    # context should have recorded start for label
    do: Range.new(Map.get(context, label, 0), offset - 1)

  # record current offset for `token_type` in `context`
  def start_mark(_rest, args, context, _line, offset, token_type),
    do: {args, Map.put(context, token_type, offset)}

  # combinator to record current offset for given `token_type`
  defp start(token_type) do
    empty()
    |> post_traverse({@m, :start_mark, [token_type]})
  end

  # SPF
  # SPF Post_traversals

  @doc """
  Post_traverse helper function that creates tokens out of a combinator result.

  A token is three element tuple: `{token_type, token_value, range}`, where:
  - `token_type` is an atom
  - `token_value` is a list of values (which may include subtokens)
  - `range` is the start..stop range of this token in the SPF string

  """
  def token(rest, args, context, line, offset, atom)
  # line = {linenr, start_of_line (0-based offset from start of entire binary)
  # offset = token_end (0-based offset from start of entire binary)

  # Whitespace
  def token(_rest, args, context, _line, offset, :whitespace) do
    {[{:whitespace, args, range(context, :whitespace, offset)}], context}
  end

  # Cidr
  def token(_rest, args, context, _line, offset, :cidr2),
    do: {[{:cidr2, Enum.reverse(args), range(context, :cidr2, offset)}], context}

  def token(_rest, args, context, _line, offset, :cidr4),
    do: {[{:cidr4, args, range(context, :cidr4, offset)}], context}

  def token(_rest, args, context, _line, offset, :cidr6),
    do: {[{:cidr6, args, range(context, :cidr6, offset)}], context}

  # DualCidr
  def token(_rest, args, context, _line, offset, :dual_cidr2),
    do: {[{:dual_cidr, Enum.reverse(args), range(context, :dual_cidr2, offset)}], context}

  def token(_rest, args, context, _line, offset, :dual_cidr4),
    do: {[{:dual_cidr, args ++ [128], range(context, :dual_cidr4, offset)}], context}

  def token(_rest, args, context, _line, offset, :dual_cidr6),
    do: {[{:dual_cidr, [32] ++ args, range(context, :dual_cidr6, offset)}], context}

  # Version
  def token(_rest, args, context, _line, offset, :version) do
    {[{:version, args, range(context, :version, offset)}], context}
  end

  # Qualifier
  def token(_rest, args, context, _line, offset, :qualifier) do
    tokval = if args == [], do: ?+, else: hd(args)
    {[{:qualifier, tokval, range(context, :qualifier, offset)}], context}
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
    [{:unknown, addr, _}, {:qualifier, q, _}] = args
    addr = List.to_string(addr)
    {[{atom, [q, addr], range(context, atom, offset)}], context}
  end

  # A/MX/PTR
  def token(_rest, args, context, _line, offset, atom) when atom in [:mx, :ptr, :a] do
    tokval =
      case Enum.reverse(args) do
        [{:qualifier, q, _range}] -> [q, []]
        [{:qualifier, q, _rang} | domspec] -> [q, domspec]
      end

    {[{atom, tokval, range(context, atom, offset)}], context}
  end

  # Literal
  def token(_rest, args, context, _line, offset, :literal) do
    {[{:literal, args, range(context, :literal, offset)}], context}
  end

  # MLiteral
  def token(_rest, args, context, _line, offset, :mliteral) do
    {[{:literal, [List.to_string(args)], range(context, :mliteral, offset)}], context}
  end

  # Transform
  def token(_rest, args, context, _line, _offset, :transform) do
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

  def token(_rest, args, context, _line, offset, :toplabel) do
    {[{:toplabel, args, range(context, :toplabel, offset)}], context}
  end

  # Expand -> {:expand, [letter, keepN, reverse?, delimiters], range}
  def token(_rest, args, context, _line, offset, :expand1) do
    [ltr, reverse, keep | delims] = Enum.reverse(args)
    delims = if delims == [], do: ["."], else: Enum.map(delims, fn x -> List.to_string([x]) end)
    tokval = [ltr, keep, reverse, delims]

    {[{:expand, tokval, range(context, :expand1, offset)}], context}
  end

  def token(_rest, args, context, _line, offset, :expand2),
    do: {[{:expand, args, range(context, :expand2, offset)}], context}

  # DomSpec
  def token(_rest, args, context, _line, offset, :domspec) when length(args) == 0,
    do: {[{:domspec, args, range(context, :domspec, offset)}], context}

  def token(_rest, args, context, _line, offset, :domspec) do
    args =
      case args do
        [{:expand, _, _} | _] -> args
        [{:toplabel, _, _} | _] -> args
        _ -> [:einvalid]
      end

    {[{:domspec, Enum.reverse(args), range(context, :domspec, offset)}], context}
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
  def token(_rest, args, context, _line, offset, :exp_str),
    do: {[{:exp_str, Enum.reverse(args), range(context, :exp_str, offset)}], context}

  # CatchAll
  def token(_rest, args, context, _line, offset, atom),
    do: {[{atom, Enum.reverse(args), range(context, atom, offset)}], context}

  # TOKENIZE

  @doc """
  Combinator that creates a token for the next SPF term in the remaining input string.
  """
  # order matters: unknown() last.
  def term() do
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

  @doc """
  Combinator that creates a list of tokens for the SPF terms found in an input string.
  """
  def tokenize(),
    do: term() |> repeat()

  # TOKENS

  # HELPERS

  @spec qualifier() :: t
  defp qualifier() do
    # Token `{:qualifier, [q], range}`.
    # When used, this combinator always produces a token where `q` defaults to `?+`.
    start(:qualifier)
    |> optional(ascii_char([?+, ?-, ?~, ??]))
    |> post_traverse({@m, :token, [:qualifier]})
  end

  defp qualifier(combinator),
    do: concat(combinator, qualifier())

  # L0 TOKENS

  @doc """
  Token `{:a, [q, tokens], range}`.

  Where
  - `q` is a [qualifier](`t:q/0`)
  - `tokens` is a list which is:
     - empty, or contains,
     - a [`domspec`](`domspec/0`) or
     - a [`dual_cidr`](`dual_cidr/0`) or
     - both.

  """
  def a() do
    start(:a)
    |> qualifier()
    |> ignore(anycase("a"))
    |> optional(domspec(":"))
    |> optional(dual_cidr())
    |> eoterm()
    |> post_traverse({@m, :token, [:a]})
  end

  @doc """
  Token `{:all, [`[`q`](`t:q/0`)`], `[`range`](`t:range/0`)`}`.
  """
  @spec all() :: t
  def all() do
    start(:all)
    |> qualifier()
    |> ignore(anycase("all"))
    |> eoterm()
    |> post_traverse({@m, :token, [:all]})
  end

  @doc """
  Token `{:exists, [q, domspec], range}`.
  """
  def exists() do
    start(:exists)
    |> qualifier()
    |> ignore(anycase("exists"))
    |> concat(domspec(":"))
    |> eoterm()
    |> post_traverse({@m, :token, [:exists]})
  end

  @doc """
  Token `{:include, [q, domspec], range}`.
  """
  @spec include() :: t
  def include() do
    start(:include)
    |> qualifier()
    |> ignore(anycase("include"))
    |> concat(domspec(":"))
    |> eoterm()
    |> post_traverse({@m, :token, [:include]})
  end

  @doc """
  Token `{:ip4, [q, address], range}`.

  Where `address` might be an IPv4 address string in CIDR notation.
  """
  def ip4() do
    start(:ip4)
    |> qualifier()
    |> ignore(anycase("ip4:"))
    |> unknown()
    |> post_traverse({@m, :token, [:ip4]})
  end

  @doc """
  Token `{:ip6, [q, address], range}`.

  Where `address` might be an IPv6 address string.
  """
  def ip6() do
    start(:ip6)
    |> qualifier()
    |> ignore(anycase("ip6:"))
    |> unknown()
    |> post_traverse({@m, :token, [:ip6]})
  end

  @doc """
  Token `{:mx, [q, domain], range}`.

  Where `domain` is a list which is
  - empty, or contains
  - a [`domspec`](`domspec/0`), or
  - a [`dual_cidr`](`dual_cidr/0`) token, or
  - both.

  """
  def mx() do
    start(:mx)
    |> qualifier()
    |> ignore(anycase("mx"))
    |> optional(domspec(":"))
    |> optional(dual_cidr())
    |> eoterm()
    |> post_traverse({@m, :token, [:mx]})
  end

  @doc """
  Token `{:ptr, [q, domspec], range}`.
  """
  def ptr() do
    start(:ptr)
    |> qualifier()
    |> ignore(anycase("ptr"))
    |> optional(domspec(":"))
    |> eoterm()
    |> post_traverse({@m, :token, [:ptr]})
  end

  @doc """
  Token `{:version, [v], range}`.

  Where `v` is an integer and should `1`.
  """
  def version() do
    start(:version)
    |> ignore(anycase("v=spf"))
    |> integer(min: 1)
    |> eoterm()
    |> post_traverse({@m, :token, [:version]})
  end

  @doc """
  Token `{:exp, [domspec], range}`.
  """
  def exp() do
    start(:exp)
    |> ignore(anycase("exp"))
    |> concat(domspec("="))
    |> eoterm()
    |> post_traverse({@m, :token, [:exp]})
  end

  @doc """
  Token `{:redirect, [domspec], range}`.
  """
  def redirect() do
    start(:redirect)
    |> ignore(anycase("redirect"))
    |> concat(domspec("="))
    |> eoterm()
    |> post_traverse({@m, :token, [:redirect]})
  end

  # L1 TOKENS

  @doc """
  Token `{:domspec, [token], range}`

  Where `token`'s include:
  - [`expand`](`expand/0`)
  - [`literal`](`literal/0`)
  - [`toplabel`](`toplabel/0`)

  Nb: a domain-spec is preceeded either by a `:` or an `=`, so higher level
  tokens need to match that themselves.

  """
  @spec domspec() :: t
  def domspec() do
    start(:domspec)
    |> times(choice([toplabel(), expand(), mliteral()]), min: 1)
    |> post_traverse({@m, :token, [:domspec]})
  end

  def domspec(str) do
    ignore(string(str))
    |> concat(domspec())
  end

  @doc """
  Token `{:dual_cidr, [len4, len6], range}`.

  Where
  - `len4` is the ipv4 cidr length (defaults to `32`)
  - `len6` is the ipv6 cidr lengths (defaults to `128`)

  This is an intermediate token used by the lexer to produce other tokens like
  [`a`](`a/0`) or [`mx`](`mx/0`) and others.

  """
  # TODO: dual_cidr's like 0+digits are illegal
  def dual_cidr() do
    choice([
      start(:dual_cidr2)
      |> ignore(string("/"))
      # |> integer(min: 1)
      |> cidrlen(2)
      |> ignore(string("//"))
      |> integer(min: 1)
      |> eoterm()
      |> post_traverse({@m, :token, [:dual_cidr2]}),
      start(:dual_cidr4)
      |> ignore(string("/"))
      # |> integer(min: 1)
      |> cidrlen(2)
      |> eoterm()
      |> post_traverse({@m, :token, [:dual_cidr4]}),
      start(:dual_cidr6)
      |> ignore(string("//"))
      |> integer(min: 1)
      |> eoterm()
      |> post_traverse({@m, :token, [:dual_cidr6]})
    ])
  end

  def cidrlen(combinator, _max) do
    concat(
      combinator,
      choice([
        lookahead(string("0")) |> integer(max: 1),
        integer(min: 1, max: 2)
      ])
    )
  end

  @doc """
  Token `{:unknown_mod, [name | subtokens], `[`range`](`t:range/0`)`}`.

  where:
  - `name` is a string
  - `subtokens` is a list of `:expand` or `:literal` macro-subtokens.

  ```
  unknown-modifier = name "=" macro-string

  name             = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )
  macro-string     = *( macro-expand / macro-literal )
  macro-expand     = ( "%{" macro-letter transformers *delimiter "}" ) / "%%" / "%_" / "%-"
  macro-literal    = %x21-24 / %x26-7E
                     ; visible characters except "%"
  ```

  """
  def unknown_mod() do
    start(:unknown_mod)
    |> concat(alpha())
    |> times(choice([alpha(), digit(), ascii_char([?-, ?_, ?.])]), min: 0)
    |> ignore(string("="))
    |> reduce({List, :to_string, []})
    |> concat(m_string())
    |> eoterm()
    |> post_traverse({@m, :token, [:unknown_mod]})
  end

  @doc """
  Token `{:unknown, [string], `[`range`](`t:range/0`)`}`.

  Used to catch unknown blobs for the parser to deal with.

  """
  @spec unknown() :: t
  def unknown() do
    # for unknown use start1, since it is also used in ip4, ip6 which are based
    # on start()
    start(:unknown)
    |> times(ascii_char(not: ?\ , not: ?\t), min: 1)
    |> post_traverse({@m, :token, [:unknown]})
  end

  @doc """
  Concatenate `unknown/0` to given `combinator`.
  """
  @spec unknown(t) :: t
  def unknown(combinator),
    do: concat(combinator, unknown())

  @doc """
  Token `{:whitespace, [string], `[`range`](`t:range/0`)`}`.

  Where `string = 1*(SP / TAB)`.

  Used to detect repreated whitespace in an SPF string and/or detect use of
  `TAB` characters which is actually not allowed.

  """
  @spec whitespace() :: t
  def whitespace() do
    start(:whitespace)
    |> times(ascii_char([?\ , ?\t]), min: 1)
    |> reduce({List, :to_string, []})
    |> post_traverse({@m, :token, [:whitespace]})
  end

  # L2 TOKENS

  @doc """
  Token `{:expand, list, `[`range`](`t:range/0`)`}`.

  Where list is either:
  - [letter, keep, reverse, split], or
  - [string]

  ```
  letter  = ?s / ?l / ?o / ?d / ?i / ?p / ?h / ?c / ?r / ?t / ?v /
            ?S / ?L / ?O / ?D / ?I / ?P / ?H / ?C / ?R / ?T / ?V
  keep    = number of parts to keep
  reverse = a boolean, indicating if reversal is required
  split   = list of splitting characters (".", "-", "+", ",", "/", "_", and/or "=")

  string  = "%" / "-" / "_"
  ```

  """
  @spec expand() :: t
  def expand() do
    choice([
      expand1(),
      expand2()
    ])
  end

  defp expand1 do
    start(:expand1)
    |> ignore(string("%{"))
    |> m_letter()
    |> m_transform()
    |> repeat(m_delimiter())
    |> ignore(string("}"))
    |> post_traverse({@m, :token, [:expand1]})
  end

  defp expand2() do
    start(:expand2)
    |> ignore(ascii_char([?%]))
    |> ascii_char([?%, ?-, ?_])
    |> reduce({List, :to_string, []})
    |> post_traverse({@m, :token, [:expand2]})
  end

  @doc """
  Token `{:literal, [string], range}`.

  Where `string = 1*( %x21-24 / %x26-7E)  ; visible characters except "%"`
  """
  @spec literal() :: t
  def literal() do
    start(:literal)
    |> times(m_literal(), min: 1)
    |> reduce({List, :to_string, []})
    |> post_traverse({@m, :token, [:literal]})
  end

  def m_string() do
    times(choice([expand(), literal()]), min: 1)
  end

  defp m_delimiter(),
    do: ascii_char([?., ?-, ?+, ?,, ?/, ?_, ?=])

  defp m_letter(),
    do:
      ascii_char(
        [?s, ?l, ?o, ?d, ?i, ?p, ?h, ?c, ?r, ?t, ?v] ++
          [?S, ?L, ?O, ?D, ?I, ?P, ?H, ?C, ?R, ?T, ?V]
      )

  defp m_letter(combinator),
    do: concat(combinator, m_letter())

  defp m_literal(),
    do: concat(lookahead_not(dual_cidr()), ascii_char([0x21..0x24, 0x26..0x7E]))

  defp m_transform() do
    # a domspec-expand without a transform will have a :transform token with
    # an empty list as token value
    times(digit(), min: 0)
    |> optional(ascii_char([?r, ?R]))
    |> post_traverse({@m, :token, [:transform]})
  end

  defp m_transform(combinator),
    do: concat(combinator, m_transform())

  # EXPLAIN
  @doc """
  Tokenizer for an explain-string.

  After expanding the domain spec of a [`exp`](`exp/0`) token into a domain name,
  its TXT RR is retrieved.  This is called the explain-string.  This function
  tokenizes this explain-string into a list of tokens:
  [`domspec`](`domspec/`), [`whitespace`](`whitespace/0`), and/or
  [`unknown`](`unknown/0`).

  The list of tokens can then be expanded into the final explanation.

  """
  def exp_str() do
    start(:exp_str)
    |> times(choice([expand(), mliteral(), whitespace()]), min: 1)
    |> post_traverse({@m, :token, [:exp_str]})
  end

  def toplabel() do
    start(:toplabel)
    |> string(".")
    |> choice([ldhlabel1(), ldhlabel2()])
    |> optional(string("."))
    |> choice([eoterm(), lookahead(dual_cidr())])
    |> reduce({List, :to_string, []})
    |> post_traverse({@m, :token, [:toplabel]})
  end

  defp ldhlabel1() do
    # start with alpha
    alpha()
    |> times(choice([dash_alphanum(), alphanum()]), min: 0)
  end

  defp ldhlabel2() do
    # starts with digit
    times(digit(), min: 1)
    |> choice([dash_alphanum(), alpha()])
    |> times(choice([dash_alphanum(), alphanum()]), min: 0)
  end

  # def cidr() do
  #   choice([
  #     start(:cidr2)
  #     |> ignore(string("/"))
  #     |> integer(min: 1)
  #     |> ignore(string("//"))
  #     |> integer(min: 1)
  #     |> post_traverse({@m, :token, [:cidr2]}),
  #     start(:cidr4)
  #     |> ignore(string("/"))
  #     |> integer(min: 1)
  #     |> post_traverse({@m, :token, [:cidr4]}),
  #     start(:cidr6)
  #     |> ignore(string("//"))
  #     |> integer(min: 1)
  #     |> post_traverse({@m, :token, [:cidr6]})
  #   ])
  # end

  defp mliteral() do
    start(:mliteral)
    |> lookahead_not(dual_cidr())
    |> ascii_char([0x21..0x24, 0x26..0x7E])
    |> post_traverse({@m, :token, [:mliteral]})
  end
end
