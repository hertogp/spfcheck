# Spfcheck


[![Test](https://github.com/hertogp/spfcheck/actions/workflows/elixir.yml/badge.svg)](https://github.com/hertogp/spfcheck/actions/workflows/elixir.yml)
[![Module Version](https://img.shields.io/hexpm/v/spfcheck.svg)](https://hex.pm/packages/spfcheck)
[![Hex Docs](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://hexdocs.pm/spfcheck/)
[![Last Updated](https://img.shields.io/github/last-commit/hertogp/spfcheck.svg)](https://github.com/hertogp/spfcheck/commits/main)
[![License](https://img.shields.io/hexpm/l/spfcheck.svg)](https://github.com/hertogp/spfcheck/blob/master/LICENSE.md)
[![Total Download](https://img.shields.io/hexpm/dt/spfcheck.svg)](https://hex.pm/packages/spfcheck)

<!-- @MODULEDOC -->

## Usage

```
Usage: spfcheck [options] sender

where sender = [localpart@]domain, localpart defaults to 'postmaster'

Options:
  -H, --help           print this message and exit
  -c, --color          use colored output (--no-color to set this to false)
  -d, --dns=filepath   file with DNS RR records to prepopulate the DNS cache
  -h, --helo=string    sending MTA's helo/ehlo identity (defaults to nil)
  -i, --ip=string      sending MTA's IPv4/IPv6 address (defaults to 127.0.0.1)
  -r, --report=string  either "all" or one of more letters of "vsewpdat" (see below)
  -v, --verbosity      set logging noise level (0..5), default is 3 (info)
```

The default is to simply print the verdict and some stats to stdout and print
informational messages to stderr.

The `-d` flag can be used to specify locally defined DNS records, which makes
it possible to try out records before publishing them in DNS.

The `-r` flag can be used to request a markdown formatted report for topics:
- `v` prints the verdict and some statistics
- `s` prints the spf records seen
- `e` prints the errors seen
- `w` prints the warnings seen
- `p` prints the prefixes collected
- `d` prints DNS information collected
- `a` prints the AST for the SPF record
- `t` prints the tokens for the SPF record

In case no `-r` flag is used, spfcheck will simply print out the verdict.

Notes:
- multiple senders can be specified on the cli
- when sender is omitted, stdin is read for domains to check, in this case:
    - the verdict fields are printed to stdout in csv-format
    - each line may specifiy its own options




## Examples:

    % spfcheck example.com
    % spfcheck  -i 1.1.1.1   --helo example.net xyz@example.com
    % spfcheck --ip=1.1.1.1 someone@example.com -d ./dns.txt

## Override DNS with local records

DNS queries are cached and the cache can be preloaded to override the live DNS
with specific records.  Useful to try out SPF records before publishing them in
DNS.  The `-d` option should point to a text file that contains 1 RR record per
line specifying the name type and rdata all on 1 line.  Note that the file is
not in BIND format and all RR's must be written in full and keys are taken
relative to root (.)

    Example dns.txt
    example.com  TXT  v=spf1 a mx exists:%{i}.example.net ~all
    example.com  TXT  verification=asdfi234098sf
    127.0.0.1.example.net A  127.0.0.1

Note that each line contains a single `name type rdata` combination, so for
multiple TXT records (e.g.) specify each on its own line, like in the example
above.  Lines that begin with '#' or \*SP'#' are ignored


## Batch mode reads from stdin

If no domains were listen on the commandline, the domains to check are read
from stdin, including possible flags that will override the ones given on the
cli itself.  Note that in this case, csv output is produced on stdout (other
logging still goes to stderr, use -v 0 to silence that)

### Examples

    % cat domains.txt
    example.net -v 0 -i 1.1.1.1 -s me@example.net
    example.com -v 0

    % cat domains.txt | spfcheck -v 0 -i 1.1.1.1
    domain,ip,sender,verdict,reason,num_spf,num_dnsm,num_dnsq,num_dnsv,num_checks,num_warn,num_error,duration,explanation
    "example.net","1.1.1.1","example.net",:fail,"spf[0] -all",1,0,1,0,2,0,0,0,""
    "example.com","127.0.0.1","example.com",:fail,"spf[0] -all",1,0,1,0,2,0,0,0,""

<!-- @MODULEDOC -->

## Installation

Use it in your project by adding `spfcheck` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:spfcheck, "~> 0.1.0"}
  ]
end
```

Or simply install `spfcheck` as an escript:

```bash
mix escript.install hex spfcheck
```

After installation, `~/.mix/escripts/spfcheck` invokes the escript.

