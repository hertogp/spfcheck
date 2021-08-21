defmodule Spf.Tokens do
  @moduledoc """
  Functions to turn an SPF string or an explain string into tokens.

  A token is represented by a `{type, value, range}`-tuple.

  Token `type`'s include:
  - [`:whitespace`](`Spf.Tokens.whitespace/0`)
  - [`:all`](`Spf.Tokens.all/0`)
  - [`:include`](`Spf.Tokens.include/0`)
  - `{dual_cidr, [len4, len6], range}`, where len4/6 are prefix lengths
  - `{:version, [num], range}`, where num should be 1
  - `{:qualifier, [q], range}`, where is one of `?+, ?-, ?~, ??`


  """

  import NimbleParsec

  @type t :: NimbleParsec.t()

  @typedoc """
  The range (`start..stop//step)` of a token in the input string.

  """
  @type range :: Range.t()

  @typedoc """
  A token represented as a tuple: {type, value, range}.

  The `value` is a list of either strings, number(s) or intermediary tokens.

  """
  @type token :: {atom, list(), range}

  @type q :: ?+ | ?- | ?~ | ??

  @m __MODULE__

  # Helpers

  @spec anycase(binary) :: t
  defp anycase(string) do
    # Combinator that matches given `string`, case-insensitive.
    string
    |> String.to_charlist()
    |> Enum.map(&bothcases/1)
    |> Enum.reduce(empty(), fn elm, acc -> concat(acc, elm) end)
  end

  # @spec anycase(t, binary) :: t
  # def anycase(combinator, string),
  #   do: concat(combinator, anycase(string))

  @spec bothcases(char) :: t
  defp bothcases(c) when ?a <= c and c <= ?z,
    do: ascii_char([c, c - 32])

  defp bothcases(c) when ?A <= c and c <= ?Z,
    do: ascii_char([c, c + 32])

  defp bothcases(c),
    do: ascii_char([c])

  defp digit(),
    do: ascii_char([?0..?9])

  # defp digit(combinator),
  #   do: concat(combinator, digit())

  defp eoterm(),
    do: lookahead(choice([whitespace(), eos()]))

  defp eoterm(c),
    do: concat(c, eoterm())

  def mark_start(_rest, _args, context, _line, offset, args \\ []),
    do: {args, Map.put(context, :start, offset)}

  defp range(context, offset),
    do: Range.new(Map.get(context, :start, 0), offset - 1)

  # TOKENS

  # token = {atom, args, range}
  # - atom is type of token
  # - args is args for Parser.token handler function
  # - range is {start, end} of token in spf string
  def token(rest, args, context, line, offset, atom)
  # line = {linenr, start_line (0-based offset from start of entire binary)
  # offset = token_end (0-based offset from start of entire binary)

  # Whitespace
  def token(_rest, args, context, _line, offset, :whitespace) do
    {[{:whitespace, args, range(context, offset)}], context}
  end

  # DualCidr
  def token(_rest, args, context, _line, offset, :dual_cidr2),
    do: {[{:dual_cidr, Enum.reverse(args), range(context, offset)}], context}

  def token(_rest, args, context, _line, offset, :dual_cidr4),
    do: {[{:dual_cidr, args ++ [128], range(context, offset)}], context}

  def token(_rest, args, context, _line, offset, :dual_cidr6),
    do: {[{:dual_cidr, [32] ++ args, range(context, offset)}], context}

  # Version
  def token(_rest, args, context, _line, offset, :version) do
    {[{:version, args, range(context, offset)}], context}
  end

  # Qualifier
  def token(_rest, args, context, _line, offset, :qualifier) do
    tokval = if args == [], do: ?+, else: hd(args)
    {[{:qualifier, tokval, range(context, offset)}], context}
  end

  # Include, Exists
  def token(_rest, args, context, _line, offset, atom) when atom in [:include, :exists] do
    [{:qualifier, q, _offset}, domain_spec] = Enum.reverse(args)
    {[{atom, [q, domain_spec], range(context, offset)}], context}
  end

  # All
  def token(_rest, args, context, _line, offset, :all) do
    [{:qualifier, q, _offset}] = args
    {[{:all, [q], range(context, offset)}], context}
  end

  # IP4, IP6
  def token(_rest, args, context, _line, offset, atom) when atom in [:ip4, :ip6] do
    [{:unknown, addr, _}, {:qualifier, q, _}] = args
    addr = List.to_string(addr)
    {[{atom, [q, addr], range(context, offset)}], context}
  end

  # A, MX, PTR
  def token(_rest, args, context, _line, offset, atom) when atom in [:a, :mx, :ptr] do
    tokval =
      case Enum.reverse(args) do
        [{:qualifier, q, _range}] -> [q, []]
        [{:qualifier, q, _rang} | domain_spec] -> [q, domain_spec]
      end

    {[{atom, tokval, range(context, offset)}], context}
  end

  # Literal
  def token(_rest, args, context, _line, offset, :literal) do
    [tokval] = args
    {[{:literal, tokval, range(context, offset)}], context}
  end

  # Transform
  def token(_rest, args, context, _line, _offset, :transform) do
    tokval =
      case args do
        [] -> [0, false]
        [?r] -> [0, true]
        [?r | tail] -> [Enum.reverse(tail) |> List.to_integer(), true]
        num -> [Enum.reverse(num) |> List.to_integer(), false]
      end

    {tokval, context}
  end

  # Expand -> {:expand, [letter, keepN, reverse?, delimiters], range}
  def token(_rest, args, context, _line, offset, :expand1) do
    [ltr, reverse, keep | delims] = Enum.reverse(args)
    delims = if delims == [], do: ["."], else: Enum.map(delims, fn x -> List.to_string([x]) end)
    tokval = [ltr, keep, reverse, delims]

    {[{:expand, tokval, range(context, offset)}], context}
  end

  def token(_rest, args, context, _line, offset, :expand2),
    do: {[{:expand, args, range(context, offset)}], context}

  # Domain_spec
  def token(_rest, args, context, _line, offset, :domain_spec),
    do: {[{:domain_spec, Enum.reverse(args), range(context, offset)}], context}

  # Redirect
  def token(_rest, args, context, _line, offset, :redirect),
    do: {[{:redirect, Enum.reverse(args), range(context, offset)}], context}

  # CatchAll
  def token(_rest, args, context, _line, offset, atom),
    do: {[{atom, Enum.reverse(args), range(context, offset)}], context}

  # order matters: all before a
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
      nonspaces()
    ])
  end

  def terms(),
    do: term() |> repeat()

  # Helper Tokens

  @doc """
  Token `{:whitespace, [string], range}`.

  Where `string = 1*(SP / TAB)`.

  Used to detect repreated whitespace in an SPF string and/or detect use of
  `TAB` characters which is actually not allowed.

  """
  @spec whitespace() :: t
  def whitespace() do
    start()
    |> times(ascii_char([?\ , ?\t]), min: 1)
    |> reduce({List, :to_string, []})
    |> post_traverse({@m, :token, [:whitespace]})
  end

  @doc """
  Token `{:unknown, [string], `[`range`](`t:range/0`)`}`.

  Used to catch unknown blobs for the parser to deal with.

  """
  @spec nonspaces() :: t
  def nonspaces() do
    # start()
    # |> ascii_char(not: ?\ , not: ?\t)
    ascii_char(not: ?\ , not: ?\t)
    |> times(min: 1)
    |> post_traverse({@m, :token, [:unknown]})
  end

  @doc """
  Concatenate `nonspaces/0` to given `combinator`.
  """
  @spec nonspaces(t) :: t
  def nonspaces(combinator),
    do: concat(combinator, nonspaces())

  @doc """
  Token `{:dual_cidr, [len4, len6], `[`range`](`t:range/0`)`}`.

  Where `len4` is the ipv4 cidr length (defaults to `32`), while `len6` is
  the ipv6 cidr lengths (defaults to `128`).  This is an intermediate token
  used by the lexer to produce other tokens like [`a`](`a/0`) or [`mx`](`mx/0`).

  """
  def dual_cidr() do
    choice([
      start()
      |> ignore(string("/"))
      |> integer(min: 1)
      |> ignore(string("//"))
      |> integer(min: 1)
      |> eoterm()
      |> post_traverse({@m, :token, [:dual_cidr2]}),
      start()
      |> ignore(string("/"))
      |> integer(min: 1)
      |> eoterm()
      |> post_traverse({@m, :token, [:dual_cidr4]}),
      start()
      |> ignore(string("//"))
      |> integer(min: 1)
      |> eoterm()
      |> post_traverse({@m, :token, [:dual_cidr6]})
    ])
  end

  # when used, this always produces a qualifier token; defaults to '+'
  @doc """
  Token `{:qualifier, [q], `[`range`](`t:range/0`)`}`.

  Where `q = ?+ / ?- / ?~ / ??`

  When used, this combinator always produces a token where `q` defaults to `?+`.

  """
  def qualifier() do
    ascii_char([?+, ?-, ?~, ??])
    |> optional()
    |> post_traverse({@m, :token, [:qualifier]})
  end

  def qualifier(combinator),
    do: concat(combinator, qualifier())

  # DIRECTIVES

  # used to mark start in context for a token combinator

  defp start() do
    empty()
    |> post_traverse({@m, :mark_start, []})
  end

  @doc """
  Token `{:version, [v], `[`range`](`t:range/0`)`}`.

  Where `v` is an integer and should `1`.
  """
  def version() do
    start()
    |> ignore(anycase("v=spf"))
    |> integer(min: 1)
    |> post_traverse({@m, :token, [:version]})
  end

  @doc """
  Token `{:all, [[`q`](`t:q/0`)], [`range`](`t:range/0`)}`.
  """
  @spec all() :: t
  def all() do
    start()
    |> qualifier()
    |> ignore(anycase("all"))
    |> post_traverse({@m, :token, [:all]})
  end

  @doc """
  Token `{:include, [`[`domain_spec`](`Spf.Tokens.domain_spec/1`)`], `[`range`](`t:range/0`)`}`.
  """
  @spec include() :: t
  def include() do
    start()
    |> qualifier()
    |> ignore(anycase("include:"))
    |> domain_spec()
    |> post_traverse({@m, :token, [:include]})
  end

  @doc """
  Token `{:ip4, [pfx4], `[`range`](`t:range/0`)`}`.

  Where `pfx4` is a `t:Pfx.t/0` struct.

  """
  def ip4() do
    start()
    |> qualifier()
    |> ignore(anycase("ip4:"))
    |> nonspaces()
    |> post_traverse({@m, :token, [:ip4]})
  end

  @doc """
  Token `{:ip6, [pfx6], `[`range`](`t:range/0`)`}`.

  Where `pfx6` is a `t:Pfx.t/0` struct.

  """
  def ip6() do
    start()
    |> qualifier()
    |> ignore(anycase("ip6:"))
    |> nonspaces()
    |> post_traverse({@m, :token, [:ip6]})
  end

  @doc """
  Token `{:a, [q, domain], `[`range`](`t:range/0`)`}`.

  Where:
  - `q = ?+ / ?- / ?~ / ??`
  - `domain` is a list which is either empty or contains a [`domain_spec`](`domain_spec/1`) or
  a [`dual_cidr`](`dual_cidr/0`) token or both.

  """
  def a() do
    start()
    |> qualifier()
    |> ignore(anycase("a"))
    |> optional(ignore(ascii_char([?:])) |> domain_spec())
    |> optional(dual_cidr())
    |> post_traverse({@m, :token, [:a]})
  end

  @doc """
  Token `{:mx, [q, domain], `[`range`](`t:range/0`)`}`.

  Where:
  - `q = ?+ / ?- / ?~ / ??`
  - `domain` is a list which is either empty or contains a [`domain_spec`](`domain_spec/1`) or
  a [`dual_cidr`](`dual_cidr/0`) token or both.

  """
  def mx() do
    start()
    |> qualifier()
    |> ignore(anycase("mx"))
    |> optional(ignore(ascii_char([?:])) |> domain_spec())
    |> optional(dual_cidr())
    |> post_traverse({@m, :token, [:mx]})
  end

  @doc """
  Token `{:exists, [q, `[`domain_spec`](`domain_spec/1`)`], `[`range`](`t:range/0`)`}`.
  """
  def exists() do
    start()
    |> qualifier()
    |> ignore(anycase("exists:"))
    |> domain_spec()
    |> post_traverse({@m, :token, [:exists]})
  end

  @doc """
  Token `{:ptr, [q, `[`domain_spec`](`domain_spec/1`)`], `[`range`](`t:range/0`)`}`.
  """
  def ptr() do
    start()
    |> qualifier()
    |> ignore(anycase("ptr"))
    |> optional(ignore(ascii_char([?:])) |> domain_spec())
    |> post_traverse({@m, :token, [:ptr]})
  end

  # MODIFIERS

  @doc """
  Token `{:redirect, `[`domain_spec`](`domain_spec/1`)`, `[`range`](`t:range/0`)`}`.
  """
  def redirect() do
    start()
    |> ignore(anycase("redirect="))
    |> domain_spec()
    |> post_traverse({@m, :token, [:redirect]})
  end

  @doc """
  Token `{:exp, `[`domain_spec`](`domain_spec/1`)`, `[`range`](`t:range/0`)`}`.
  """
  def exp() do
    start()
    |> ignore(anycase("exp="))
    |> domain_spec()
    |> post_traverse({@m, :token, [:exp]})
  end

  @doc """
  Tokenizer for an explain-string.

  After expanding the domain spec of a [`exp`](`exp/0`) token into a domain name,
  its TXT RR is retrieved.  This is called the explain-string.  This function
  tokenizes this explain-string into a list of tokens:
  [`domain_spec`](`domain_spec/`), [`whitespace`](`whitespace/0`), and/or
  [`nonspaces`](`nonspaces/0`).

  The list of tokens can then be expanded into the final explanation.

  """
  def exp_str() do
    start()
    |> choice([
      domain_spec(),
      whitespace(),
      nonspaces()
    ])
    |> times(min: 1)
    |> post_traverse({@m, :token, [:exp_str]})
  end

  # DOMAIN-SPEC

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

  defp literal(),
    do: ascii_char([0x21..0x24, 0x26..0x7E])

  @doc """
  Token `{:literal, value, range}`.

  Where `value = = 1*( %x21-24 / %x26-7E)  ; visible characters except "%"`
  """
  @spec literal(t) :: t
  def literal(combinator),
    do: concat(combinator, literal())

  # a domain_spec-expand without a transform will have a :transform token with
  # an empty list as token value
  defp m_transform() do
    times(digit(), min: 0)
    |> optional(ascii_char([?r]))
    |> post_traverse({@m, :token, [:transform]})
  end

  defp m_transform(combinator),
    do: concat(combinator, m_transform())

  @doc """
  Token `{:expand, [l, N, reverse, split], `[`range`](`t:range/0`)`}`.

  Where
  ```
  l = ?s / ?l / ?o / ?d / ?i / ?p / ?h / ?c / ?r / ?t / ?v /
      ?S / ?L / ?O / ?D / ?I / ?P / ?H / ?C / ?R / ?T / ?V
  N = number of parts to keep
  reverse = a boolean, indicating if reversal is required
  split = list of splitting characters (?. / ?- / ?+ / ?, / ?/ / ?_ / ?=)
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
    ignore(string("%{"))
    |> m_letter()
    |> m_transform()
    |> repeat(m_delimiter())
    |> ignore(string("}"))
    |> post_traverse({@m, :token, [:expand1]})
  end

  defp expand2() do
    ignore(ascii_char([?%]))
    |> ascii_char([?%, ?-, ?_])
    |> reduce({List, :first, []})
    |> post_traverse({@m, :token, [:expand2]})
  end

  defp m_literals() do
    lookahead_not(dual_cidr())
    |> literal()
    |> times(min: 1)
    |> reduce({List, :to_string, []})
    |> post_traverse({@m, :token, [:literal]})
  end

  defp domain_spec() do
    choice([
      expand(),
      m_literals()
    ])
    |> times(min: 1)
    |> post_traverse({@m, :token, [:domain_spec]})
  end

  @doc """
  Token `{:domain_spec, value, range}`.

  Where `value` is a list of one or more:
  - [`expand`](`expand/0`)
  - [`literal`](`literal/1`)
  tokens in any order.
  """
  @spec domain_spec(t) :: t
  def domain_spec(combinator) do
    concat(combinator, domain_spec())
  end
end
