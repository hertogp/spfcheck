defmodule Spf.Helpers do
  @moduledoc """
  Helper functions for parsing SPF records
  """

  import NimbleParsec

  # Helpers
  def anycase(string) do
    string
    |> String.to_charlist()
    |> Enum.map(&bothcases/1)
    |> Enum.reduce(empty(), fn elm, acc -> concat(acc, elm) end)
  end

  def anycase(combinator, string),
    do: concat(combinator, anycase(string))

  def bothcases(c) when ?a <= c and c <= ?z,
    do: ascii_char([c, c - 32])

  def bothcases(c) when ?A <= c and c <= ?Z,
    do: ascii_char([c, c + 32])

  def bothcases(c),
    do: ascii_char([c])

  # def name() do
  #   ascii_char(not: ?\ , not: ?:, not: ?=)
  #   |> times(min: 1)
  #   |> reduce({IO, :iodata_to_binary, []})
  #   |> post_traverse({:token, [:name]})
  # end

  # def name(combinator),
  #   do: concat(combinator, name())

  # def sep() do
  #   choice([
  #     ascii_char([?:, ?=]),
  #     empty()
  #   ])
  #   |> post_traverse({:token, [:sep]})
  # end

  # def sep(combinator),
  #   do: concat(combinator, sep())

  def digit(),
    do: ascii_char([?0..?9])

  def digit(combinator),
    do: concat(combinator, digit())

  # -> TODO, remove once Pfx.parse becomes available
  defp pfxparse(pfx) do
    Pfx.new(pfx)
  rescue
    _ -> {:error, pfx}
  end

  @doc """
  Matches 1 or more spaces

  """
  def spaces() do
    ascii_char([?\ ])
    |> times(min: 1)
    |> reduce({List, :to_string, []})
    |> post_traverse({:token, [:whitespace]})
  end

  @doc """
  Matches one or more non-space characters as a catch all for unknown blobs

  """
  def nonspaces(),
    do: ascii_char(not: ?\ ) |> times(min: 1) |> post_traverse({:token, [:unknown]})

  def nonspaces(combinator),
    do: concat(combinator, nonspaces())

  def eoterm() do
    choice([
      ascii_char([32, ?\t]),
      eos()
    ])
    |> lookahead()
  end

  def eoterm(combinator),
    do: concat(combinator, eoterm())

  def dual_cidr_length() do
    choice([
      ignore(string("/"))
      |> integer(min: 1)
      |> ignore(string("//"))
      |> integer(min: 1)
      |> post_traverse({:token, [:dual_cidr2]}),
      ignore(string("//"))
      |> integer(min: 1)
      |> post_traverse({:token, [:dual_cidr6]}),
      ignore(string("/"))
      |> integer(min: 1)
      |> post_traverse({:token, [:dual_cidr4]})
    ])
    |> eoterm()
  end

  # TOKENS

  # Qualifier
  def token(_rest, args, context, _line, offset, :qualifier) do
    case args do
      [] -> {[{:qualifier, ?+, offset}], context}
      [q] -> {[{:qualifier, q, offset - 1}], context}
    end
  end

  # All
  def token(_rest, args, context, _line, _offset, :all) do
    [{:qualifier, q, off}] = args
    {[{:all, q, off}], context}
  end

  # IP4
  def token(_rest, args, context, _line, _offset, :ip4) do
    [{:unknown, ip4, _}, {:qualifier, q, offset}] = args
    ip4 = List.to_string(ip4) |> pfxparse()
    {[{:ip4, q, ip4, offset}], context}
  end

  # IP6
  def token(_rest, args, context, _line, _offset, :ip6) do
    [{:unknown, ip6, _}, {:qualifier, q, offset}] = args
    ip6 = List.to_string(ip6) |> pfxparse()
    {[{:ip6, q, ip6, offset}], context}
  end

  # Version
  def token(_rest, args, context, _line, offset, :version) do
    n = List.first(args)
    d = length(Integer.digits(n))
    {[{:version, n, offset - 5 - d}], context}
  end

  # Literal
  def token(_rest, args, context, _line, offset, :literal) do
    [literal] = args
    {[{:literal, literal, offset - String.length(literal)}], context}
  end

  # Transform
  def token(_rest, args, context, _line, offset, :transform) do
    tokval =
      case args do
        [] -> []
        [?r | tail] -> [Enum.reverse(tail) |> List.to_integer(), r: true]
        num -> [Enum.reverse(num) |> List.to_integer(), r: false]
      end

    {[{:transform, tokval, offset - length(args)}], context}
  end

  # Expand
  def token(_rest, args, context, _line, _offset, :expand1) do
    [{:transform, _, offset}, _] = args
    {[{:expand, Enum.reverse(args), offset - 3}], context}
  end

  def token(_rest, args, context, _line, offset, :expand2) do
    {[{:expand, args, offset - 2}], context}
  end

  # Macro
  def token(_rest, args, context, _line, offset, :macro) do
    # a macro string begins at the same offset as its first matched token
    args = Enum.reverse(args)

    offset =
      case List.first(args) do
        {_atom, _args, off} -> off
        str when is_binary(str) -> offset - String.length(str)
      end

    {[{:macro, args, offset}], context}
  end

  # Whitespace
  def token(_rest, args, context, _line, offset, :whitespace) do
    tokval = List.first(args)
    {[{:whitespace, tokval, offset - String.length(tokval)}], context}
  end

  # CatchAll
  def token(_rest, args, context, _line, offset, atom) do
    args = Enum.reverse(args)
    {[{atom, args, offset}], context}
  end

  # DIRECTIVES

  def qualifier() do
    ascii_char([?+, ?-, ?~, ??])
    |> optional()
    |> post_traverse({:token, [:qualifier]})
  end

  def qualifier(combinator),
    do: concat(combinator, qualifier())

  # order matters: all before a
  def term() do
    choice([
      version(),
      redirect(),
      explanation(),
      all(),
      a(),
      mx(),
      include(),
      ip4(),
      ip6(),
      exists(),
      ptr(),
      spaces(),
      nonspaces()
    ])
  end

  def term(combinator),
    do: concat(combinator, term())

  def terms(),
    do: term() |> repeat()

  def version() do
    anycase("v=spf")
    |> ignore()
    |> integer(min: 1)
    |> post_traverse({:token, [:version]})
  end

  def all() do
    qualifier()
    |> ignore(anycase("all"))
    |> post_traverse({:token, [:all]})
  end

  def include() do
    qualifier()
    |> ignore(anycase("include:"))
    |> macro()
    |> pre_traverse({:token, [:include]})
  end

  def ip4() do
    qualifier()
    |> ignore(anycase("ip4:"))
    |> nonspaces()
    |> post_traverse({:token, [:ip4]})
  end

  def ip6() do
    qualifier()
    |> ignore(anycase("ip6:"))
    |> nonspaces()
    |> post_traverse({:token, [:ip6]})
  end

  # a = "a" [ ":" domain-spec ] [ dual-cidr-length ]
  def a() do
    qualifier()
    |> ignore(anycase("a"))
    |> optional(ignore(ascii_char([?:])) |> macro())
    |> optional(dual_cidr_length())
    |> post_traverse({:token, [:a]})
  end

  def mx() do
    qualifier()
    |> ignore(anycase("mx"))
    |> optional(ignore(ascii_char([?:])) |> macro())
    |> optional(dual_cidr_length())
    |> post_traverse({:token, [:mx]})
  end

  def exists() do
    qualifier()
    |> ignore(anycase("exists:"))
    |> macro()
    |> post_traverse({:token, [:exists]})
  end

  def ptr() do
    qualifier()
    |> ignore(anycase("ptr"))
    |> optional(ignore(ascii_char([?:])) |> macro())
    |> post_traverse({:token, [:ptr]})
  end

  # MODIFIERS
  def redirect() do
    anycase("redirect=")
    |> ignore()
    |> macro()
    |> post_traverse({:token, [:redirect]})
  end

  def explanation() do
    anycase("exp=")
    |> ignore()
    |> macro()
    |> post_traverse({:token, [:exp]})
  end

  # MACROS

  # Notes:
  # - since a macro-string also matches a domain-end, we match a domain-spec
  #   as a series of m_expand, dual_cidr_length or m_literal's (in that order)
  # - hence, post processing will have to check toplabel validity if the last
  #   element in a :macro value is a binary.
  def m_delimiter(),
    do: ascii_char([?., ?-, ?+, ?,, ?/, ?_, ?=])

  def m_delimiter(combinator),
    do: concat(combinator, m_delimiter())

  def m_letter(),
    do:
      ascii_char(
        [?s, ?l, ?o, ?d, ?i, ?p, ?h, ?c, ?r, ?t, ?v] ++
          [?S, ?L, ?O, ?D, ?I, ?P, ?H, ?C, ?R, ?T, ?V]
      )

  def m_letter(combinator),
    do: concat(combinator, m_letter())

  def m_literal() do
    ascii_char([0x21..0x24, 0x26..0x7E])
    |> times(min: 1)
    |> reduce({IO, :iodata_to_binary, []})
    |> post_traverse({:token, [:literal]})
  end

  def m_literal(combinator),
    do: concat(combinator, m_literal())

  def m_transform() do
    times(digit(), min: 0)
    |> optional(ascii_char([?r]))
    |> post_traverse({:token, [:transform]})
  end

  def m_transform(combinator),
    do: concat(combinator, m_transform())

  def m_expand() do
    choice([
      m_expand1(),
      m_expand2()
    ])
  end

  def m_expand1 do
    ignore(string("%{"))
    |> m_letter()
    |> m_transform()
    |> repeat(m_delimiter())
    |> ignore(string("}"))
    |> post_traverse({:token, [:expand1]})
  end

  def m_expand2() do
    ignore(ascii_char([?%]))
    |> ascii_char([?%, ?-, ?_])
    |> reduce({List, :first, []})
    |> post_traverse({:token, [:expand2]})
  end

  def macro() do
    times(
      choice([
        m_expand(),
        lookahead_not(choice([m_expand(), dual_cidr_length()]))
        |> ascii_char([0x21..0x24, 0x26..0x7E])
        |> times(min: 1)
        |> reduce({IO, :iodata_to_binary, []})
      ]),
      min: 1
    )
    |> post_traverse({:token, [:macro]})
  end

  def macro(combinator) do
    concat(combinator, macro())
  end
end
