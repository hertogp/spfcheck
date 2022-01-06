defmodule Spf.Lexer do
  @moduledoc """
  Lexer for SPF strings and explain-strings.

  See [the collected ABNF](https://www.rfc-editor.org/rfc/rfc7208.html#section-12).
  """

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
  - an explain string: `:exp_str`,
  - an unknown modifier: `:unknown`,
  - a syntax error: `:error`
  - whitespace: `:whitespace`,
  - a subtoken: `:expand, :literal, :cidr`

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

  The `:error` token is tried as a last resort and matches any non-space
  sequence.  When matched, it means the SPF string has a syntax error.

  """
  @type type ::
          :a
          | :all
          | :exists
          | :exp
          | :include
          | :ip4
          | :ip6
          | :mx
          | :ptr
          | :redirect
          | :unknown
          | :version
          | :whitespace
          # catch all
          | :error
          # explain-string
          | :exp_str
          # subtokens
          | :cidr
          | :expand
          | :literal

  @typedoc """
  A token represented as a tuple: `{type, list, range}`.

  Where:
  - `type` is an atom which denotes the token `t:type/0`
  - `list` may be empty or contain one or more values (including subtokens)
  - `range` is the `start..stop`-slice in the input string

  """
  @type token :: {type, list(), range}

  @typedoc """
  An ok/error tuple produced by lexing some input
  """
  @type result :: {:ok, [token], binary, map} | {:error, atom, binary, map}

  @typedoc """
  A lexer is a function that takes a binary & a lexer-context, and returns a `t:result/0`
  """
  @type lexer :: (binary, map -> result)

  @wspace [?\s, ?\t]
  @eoterm @wspace ++ [-1]
  @mdelimiters [?., ?-, ?+, ?,, ?/, ?_, ?=]
  @mletters [?s, ?l, ?o, ?d, ?i, ?p, ?h, ?c, ?r, ?t, ?v] ++
              [?S, ?L, ?O, ?D, ?I, ?P, ?H, ?C, ?R, ?T, ?V]

  # when used to slice a string -> yields ""
  @null_slice 1..0//-1

  @doc """
  Returns a lexer `t:result/0` after consuming an SPF string.

  The SPF string can be a full SPF TXT string or a partial string.
  The lexer produces a list of tokens found, including a catch-all
  `:error` token for character sequences that were not recognized.

  ## Example

      iex> {:ok, tokens, _rest, _map} = Spf.Lexer.tokenize_spf("a:%{d}")
      iex> tokens
      [{:a, [43, {:expand, [100, -1, false, ["."]], 2..5}, {:cidr, [32, 128], 1..0//-1}], 0..5}]

  """
  @spec tokenize_spf(binary) :: result
  def tokenize_spf(input) when is_binary(input),
    do: spf_tokenize().(input, %{offset: 0, input: input})

  @doc """
  Returns a lexer `t:result/0` after consuming an explain-string.

  An explaing-string is the TXT RR value of the domain specified by the
  domain specification of the `exp`-modifier and is basically a series
  of macro-strings and spaces.  This is the only time `c`, `r`, `t`-macros
  may be used.

  The lexer produces an `:error` token for character-sequences it doesn't know.

  ## Example

      iex> {:ok, tokens, _rest, _map} = Spf.Lexer.tokenize_exp("timestamp %{t}")
      iex> tokens
      [
        {:exp_str,
         [{:literal, ["timestamp"], 0..8},
          {:whitespace, [" "], 9..9},
          {:expand, [116, -1, false, ["."]], 10..13}
         ], 0..13}
      ]

  """
  @spec tokenize_exp(binary) :: result
  def tokenize_exp(input) when is_binary(input),
    do: exp_tokenize().(input, %{offset: 0, input: input})

  # Context Helpers

  @spec del(map, atom) :: map
  defp del(map, name),
    do: Map.delete(map, name)

  @spec range(map, atom) :: range
  defp range(map, name) do
    # note: if stop < start -> a token is being generated out of nothing
    start = Map.get(map, name, 0)
    stop = Map.get(map, :offset) - 1

    cond do
      start > stop -> @null_slice
      true -> start..stop
    end
  end

  @spec set(map, atom) :: map
  defp set(map, name) do
    # record current offset for given `name`
    Map.put(map, name, map.offset)
  end

  @spec upd(map, binary) :: map
  defp upd(map, rest) do
    # update offset after some input was accepted by some parser
    offset = map.offset + String.length(map.input) - String.length(rest)

    Map.put(map, :offset, offset)
    |> Map.put(:input, rest)
  end

  # Tokenizers

  @spec spf_tokenize :: lexer
  defp spf_tokenize() do
    choice([
      whitespace(),
      # mechanisms
      mechanism(:a),
      mechanism(:mx),
      mechanism(:ip4),
      mechanism(:ip6),
      mechanism(:include),
      mechanism(:exists),
      mechanism(:ptr),
      mechanism(:all),
      # modifiers
      modifier(:redirect),
      modifier(:v),
      modifier(:exp),
      modifier(:unknown),
      # catch all
      error()
    ])
    |> many()
  end

  @spec exp_tokenize :: lexer
  defp exp_tokenize() do
    choice([whitespace(), mstring() |> satisfy(fn l -> l != [] end), error()])
    |> many()
    |> map(fn l -> List.flatten(l) end)
    |> mark(:exp_str)
    |> map(fn token -> [token] end)
  end

  # Token parsers

  @spec error :: lexer
  defp error() do
    until(fn c -> c in @eoterm end)
    |> map(fn chars -> [to_string(chars)] end)
    |> mark(:error)
  end

  @spec mechanism(atom) :: lexer
  defp mechanism(key) when key in [:a, :mx] do
    choice([
      sequence([qualifier(), keyword(key, eot())])
      |> map(fn [q, _key] -> [q, default_cidr([])] end),
      sequence([qualifier(), keyword(key, char1(?/)), cidr()])
      |> map(fn [q, _key, cidr] -> [q, cidr] end),
      sequence([
        qualifier(),
        keyword(key, char1(?:)),
        char1(?:),
        choice([expand(), literals(), merror()])
        |> until(eot())
        |> satisfy(fn x -> x != [] end)
      ])
      |> map(fn [q, _key, _skip, terms] -> cidr_check(key, [q | terms]) end)
    ])
    |> mark(key)
  end

  defp mechanism(:ptr) do
    choice([
      sequence([qualifier(), keyword(:ptr, eot())])
      |> map(fn [q, _key] -> [q] end),
      sequence([
        qualifier(),
        keyword(:ptr, char1(?:)),
        char1(?:),
        choice([expand(), literals(), merror()])
        |> until(eot())
        |> satisfy(fn x -> x != [] end)
      ])
      |> map(fn [q, _key, _skip, terms] -> [q | terms] end)
    ])
    |> mark(:ptr)
  end

  defp mechanism(:all) do
    sequence([qualifier(), keyword(:all, eot())])
    |> map(fn [q, _key] -> [q] end)
    |> mark(:all)
  end

  defp mechanism(key) do
    # mechanisms :ip4, :ip6, :include, :exists
    sequence([
      qualifier(),
      keyword(key, char1(?:)),
      char1(?:),
      choice([expand(), literals(), merror()])
      |> until(eot())
      |> satisfy(fn x -> x != [] end)
    ])
    |> map(fn [q, _key, _skip, terms] -> cidr_check(key, [q | terms]) end)
    |> mark(key)
  end

  @spec modifier(atom) :: lexer
  defp modifier(:v) do
    sequence([
      keyword(:v, char1(?=)),
      char1(?=),
      keyword(:spf, number()),
      number(),
      eot()
    ])
    |> map(fn [_v, _is, _spf, n, _eot] -> [n] end)
    |> mark(:version)
  end

  defp modifier(:unknown) do
    # name = *( expand / literal )
    sequence([name(), char1(?=), mstring()])
    |> map(fn [name, _, macro_string] -> List.flatten([name, macro_string]) end)
    |> mark(:unknown)
  end

  defp modifier(key) do
    sequence([
      keyword(key, char1(?=)),
      char1(?=),
      choice([expand(), literals(), merror()])
      |> until(eot())
      |> map(fn l -> if l == [], do: [{:error, [""], @null_slice}], else: l end)
      # |> satisfy(fn x -> x != [] end)
    ])
    |> map(fn [_key, _skip, terms] -> cidr_check(key, terms) end)
    |> mark(key)
  end

  @spec whitespace() :: lexer
  defp whitespace() do
    until(fn c -> c not in @wspace end)
    |> map(fn chars -> [to_string(chars)] end)
    |> mark(:whitespace)
  end

  # TokenParser Helpers

  @spec cidr_check(atom, [token]) :: [token]
  defp cidr_check(key, tokens) when key in [:a, :mx] do
    with {:literal, [str], range} <- List.last(tokens),
         context <- %{offset: range.first, input: str},
         {:ok, [literal, cidr], "", _} <- cidr_lex().(str, context) do
      case literal do
        {:literal, [""], @null_slice} -> List.replace_at(tokens, -1, cidr)
        _ -> List.replace_at(tokens, -1, literal) |> List.insert_at(-1, cidr)
      end
    else
      _ -> List.insert_at(tokens, -1, {:cidr, [32, 128], @null_slice})
    end
  end

  defp cidr_check(_key, tokens),
    do: tokens

  @spec cidr_lex() :: lexer
  defp cidr_lex() do
    # parse the last cidr from a literal string and return [lead_literal, cidr_or_default]
    sequence([
      char()
      |> until(choice([cidr(), eot()]))
      |> map(fn l -> [to_string(l)] end)
      |> mark(:literal),
      optional(cidr()) |> map(&default_cidr/1)
    ])
  end

  @spec default_cidr(list) :: list
  defp default_cidr(l),
    do: if(l == [], do: {:cidr, [32, 128], @null_slice}, else: l)

  @spec default_mdelims(list) :: list
  defp default_mdelims(l),
    do: if(l == [], do: ["."], else: Enum.map(l, fn n -> to_string([n]) end))

  defp expand() do
    # note: keep param defaults to -1, since keep==0 is actually valid (albeit useless)
    choice([
      sequence([
        keyword("%{"),
        any(@mletters),
        optional(number()) |> map(fn x -> if x == [], do: -1, else: x end),
        optional(keyword("r")) |> map(fn x -> if x == [], do: false, else: true end),
        optional(any(@mdelimiters) |> many()) |> map(&default_mdelims/1),
        keyword("}")
      ])
      |> map(fn [_, ltr, keep, reverse, delims, _] -> [ltr, keep, reverse, delims] end)
      |> mark(:expand),
      keyword("%%") |> map(fn _ -> ["%"] end) |> mark(:expand),
      keyword("%-") |> map(fn _ -> ["-"] end) |> mark(:expand),
      keyword("%_") |> map(fn _ -> ["_"] end) |> mark(:expand)
    ])
  end

  defp mliteral?(c),
    do: 0x21 <= c and c <= 0x7E and c != 0x25

  defp mstring(),
    do: choice([expand(), literals(), merror()]) |> until(eot())

  defp merror() do
    char()
    |> satisfy(fn _ -> true end)
    |> map(fn l -> [to_string([l])] end)
    |> mark(:error)
  end

  defp literals() do
    until(fn c -> not mliteral?(c) end)
    |> map(fn l -> [List.flatten(l) |> to_string()] end)
    |> mark(:literal)
  end

  # SPF parsers
  # token = {:type, list, range}
  # subtokens may have null_slice as range (i.e. they're defaults, not present in input)

  defp cidr() do
    # cidr can only match if it ends a term
    choice([
      sequence([cidr4(), cidr6()]),
      cidr4() |> map(fn n -> [n, 128] end),
      cidr6() |> map(fn n -> [32, n] end)
    ])
    |> eot()
    |> mark(:cidr)
  end

  defp cidr4() do
    # just lex the number, parser will check validity (incl. leading zeros)
    sequence([char1(?/), number()])
    |> map(fn [_, number] -> number end)
  end

  defp cidr6() do
    # just lex the number, parser will check validity
    sequence([char1(?/), char1(?/), number()])
    |> map(fn [_, _, number] -> number end)
  end

  defp qualifier() do
    # when used always yields a qualifier
    any([?+, ?-, ?~, ??])
    |> optional()
    |> map(fn x -> if x == [], do: ?+, else: x end)
  end

  # GENERIC Parsers > return parser results

  defp any(codepoints),
    do: char() |> satisfy(fn c -> c in codepoints end)

  defp alpha(),
    do: char() |> satisfy(fn x -> (?a <= x and x <= ?z) or (?A <= x and x <= ?Z) end)

  defp alnum(),
    do: choice([alpha(), digit()])

  defp char1(expected),
    do: char() |> satisfy(fn x -> x == expected end)

  defp digit(),
    do: char() |> satisfy(fn x -> ?0 <= x and x <= ?9 end)

  defp keyword(expected) do
    to_string(expected)
    |> anycase(empty())
    |> map(fn _ -> expected end)
  end

  defp keyword(expected, accept) do
    to_string(expected)
    |> anycase(accept)
    |> map(fn _ -> expected end)
  end

  defp name() do
    sequence([alpha(), choice([alnum(), any([?., ?_, ?-])]) |> many()])
    |> satisfy(fn list -> list != [] end)
    |> map(fn chars -> to_string(chars) end)
  end

  defp number() do
    sequence([digit(), digit() |> many()])
    |> map(fn digits -> List.flatten(digits) |> List.to_integer() end)
  end

  # COMBINATORS > return a parser function
  # @spec parser_fun: (binary, map) -> {:error, reason, input, ctx} | {:ok, terms, rest, upd(ctx, rest)}
  defp anycase(str, accept) do
    fn input, ctx ->
      want = String.upcase(str)
      {have, rest} = String.split_at(input, String.length(want))

      with {:ok, _, _, _} <- accept.(rest, ctx) do
        if want == String.upcase(have),
          do: {:ok, str, rest, upd(ctx, rest)},
          else: {:error, :anycase, input, ctx}
      end
    end
  end

  defp empty(),
    do: fn input, ctx -> {:ok, [], input, ctx} end

  defp char() do
    fn input, ctx ->
      case input do
        "" -> {:error, :eos, input, ctx}
        <<byte::8, rest::binary>> -> {:ok, byte, rest, ctx}
      end
    end
  end

  defp choice(parsers) do
    fn input, ctx ->
      case parsers do
        [] ->
          {:error, :choice, input, ctx}

        [first | others] ->
          with {:error, _, _, ctx} <- first.(input, ctx),
               do: choice(others).(input, ctx)
      end
    end
  end

  defp eot() do
    # end of term means wspace is next or end of input
    fn input, ctx ->
      c =
        case input do
          "" -> -1
          <<c::8, _rest::binary>> -> c
        end

      if c in @eoterm,
        do: {:ok, [], input, ctx},
        else: {:error, :eot, input, ctx}
    end
  end

  defp eot(parser) do
    # usage: parser() |> eot()
    fn input, ctx ->
      with {:ok, term, rest, ctx} <- parser.(input, ctx),
           {:ok, _, _, _} <- eot().(rest, ctx),
           do: {:ok, term, rest, upd(ctx, rest)}
    end
  end

  defp many(parser) do
    # note, applies `parser` 0 or more times:
    # - if `parser` *never* fails, this will loop forever!
    # - if having one many inside another many, it'll loop forever as well
    fn input, ctx ->
      case parser.(input, ctx) do
        {:error, _, _, ctx} ->
          {:ok, [], input, ctx}

        {:ok, term, rest, ctx} ->
          {:ok, terms, rest, ctx} = many(parser).(rest, ctx)
          {:ok, [term | terms], rest, upd(ctx, rest)}
      end
    end
  end

  defp mark(parser, name) do
    fn input, ctx ->
      with {:ok, term, rest, ctx} <- parser.(input, set(ctx, name)) do
        {:ok, {name, term, range(ctx, name)}, rest, del(ctx, name)}
      end
    end
  end

  defp map(parser, mapper) do
    fn input, ctx ->
      with {:ok, term, rest, ctx} <- parser.(input, ctx),
           do: {:ok, mapper.(term), rest, ctx}
    end
  end

  defp satisfy(parser, accept) do
    fn input, ctx ->
      with {:ok, term, rest, ctx} <- parser.(input, ctx) do
        if accept.(term),
          do: {:ok, term, rest, upd(ctx, rest)},
          else: {:error, :reject, rest, ctx}
      end
    end
  end

  defp optional(parser) do
    fn input, ctx ->
      with {:error, _, _, ctx} <- parser.(input, ctx),
           do: {:ok, [], input, ctx}
    end
  end

  defp sequence(parsers) do
    fn input, ctx ->
      case parsers do
        [] ->
          {:ok, [], input, ctx}

        [first | others] ->
          with {:ok, term, rest, ctx_s} <- first.(input, ctx),
               {:ok, terms, rest, ctx_s} <- sequence(others).(rest, ctx_s) do
            {:ok, [term | terms], rest, ctx_s}
          else
            _ -> {:error, :sequence, input, ctx}
          end
      end
    end
  end

  defp until(stop) when is_function(stop, 1) do
    # gobble up chars until stop function says so or till eos
    fn input, ctx ->
      {char, rest} =
        case input do
          "" -> {-1, ""}
          <<c::8, rest::binary>> -> {c, rest}
        end

      if stop.(char) do
        if input == ctx.input,
          do: {:error, :until, input, ctx},
          else: {:ok, [], input, ctx}
      else
        with {:ok, chars, rest, ctx} <- until(stop).(rest, ctx),
             do: {:ok, [char | chars], rest, upd(ctx, rest)}
      end
    end
  end

  defp until(parser, stop) when is_function(stop, 2) do
    # apply parser 0 or more times, until stop parser says so or fail
    # - note: if parser fails before stop says to stop, nothing is parsed
    fn input, ctx ->
      case stop.(input, ctx) do
        {:ok, _, _, _} ->
          {:ok, [], input, ctx}

        _ ->
          with {:ok, term, rest, ctx} <- parser.(input, ctx),
               {:ok, terms, rest, ctx} <- until(parser, stop).(rest, ctx) do
            {:ok, [term | terms], rest, upd(ctx, rest)}
          end
      end
    end
  end
end
