defmodule Spf.Tokenizer do
  @moduledoc false

  import NimbleParsec
  defparsec(:tokenize_spf, Spf.Tokens.tokenize_spf())
  defparsec(:tokenize_exp, Spf.Tokens.tokenize_exp())
end
