# Spfcheck


[![Test](https://github.com/hertogp/spfcheck/actions/workflows/elixir.yml/badge.svg)](https://github.com/hertogp/spfcheck/actions/workflows/elixir.yml)
[![Module Version](https://img.shields.io/hexpm/v/spfcheck.svg)](https://hex.pm/packages/spfcheck)
[![Hex Docs](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://hexdocs.pm/spfcheck/)
[![Last Updated](https://img.shields.io/github/last-commit/hertogp/spfcheck.svg)](https://github.com/hertogp/spfcheck/commits/main)
[![License](https://img.shields.io/hexpm/l/spfcheck.svg)](https://github.com/hertogp/spfcheck/main/LICENSE.md)
[![Total Download](https://img.shields.io/hexpm/dt/spfcheck.svg)](https://hex.pm/packages/spfcheck)

<!-- @MODULEDOC -->

`spfcheck` is a command line tool to examine and debug SPF records.

```txt
Usage: spfcheck [options] [sender ...]

where sender = [localpart@]domain and localpart defaults to 'postmaster'

Options:
  -H, --help           print this message and exit
  -d, --dns=filepath   file with DNS RR records to prepopulate the DNS cache
  -h, --helo=string    sending MTA helo/ehlo identity (defaults to nil)
  -i, --ip=string      sending MTA IPv4/IPv6 address (defaults to 127.0.0.1)
  -r, --report=string  either "all" or one of more letters of "vsewpdat" (see below)
  -v, --verbosity      set logging noise level (0..5), default is 4 (informational)
  -w, --width=NUM      limits line length to increase readability (defaults to 60)
  --no-color           turn off colors for log messages
  --no-markdown        turn off markdown formatting for reports
```

The default is to simply print the verdict and some stats to stdout and print
notification messages to stderr.  `spfcheck` passes the
[`rfc7208 test suite`](http://http://www.open-spf.org/Test_Suite)
and should be reasonably
[`rfc7208`](https://www.rfc-editor.org/rfc/rfc7208.html) compliant.

If no `sender` is given on the command line, `spfcheck` will read stdin for the
domains (and options) to check.  In this case, the verdict(s) are output on
stdout in csv-format as each domain is (sequentially) evaluated.

```txt
% cat domains.txt
example.com
example.net -i 1.2.3.4 -s someone@example.net

% cat domains.txt | spfcheck -v 0
domain,ip,sender,verdict,reason,num_spf,num_dnsm,num_dnsq,num_dnsv,num_checks,num_warn,num_error,duration,explanation
"example.com","127.0.0.1","example.com",:fail,"spf[0] -all",1,0,1,0,1,0,0,0,""
"example.net","1.2.3.4","example.net",:fail,"spf[0] -all",1,0,1,0,1,0,0,1,""
```

The `-d` flag can be used to either point to local file with RR-records or
specify DNS data on the command line.  If the file exists, it is read and used
to prepopulate the cache. Otherwise, the text will be read as DNS data.  This
makes it possible to try out records before publishing them in DNS.  That file
should contain 1 RR record per line using the simple `domain  type  rdata`
format. All `domain`'s are taken to be relative to root ('.').

```txt
% spfcheck example.com -v 0 -d "example.com TXT v=spf1 +all"
domain     : example.com
ip         : 127.0.0.1
sender     : example.com
verdict    : pass
reason     : spf[0] +all
num_spf    : 1
num_dnsm   : 0
num_dnsq   : 1
num_dnsv   : 0
num_checks : 1
num_warn   : 0
num_error  : 0
duration   : 1
explanation: 


Or using a file


% cat tmp/zonedata.txt
# comments are ignored as are empty lines

example.com     TXT  v=spf1 -all exp=why.%{d}
example.com     TXT  just another txt record
why.example.com TXT  %{d}: %{i} is not one of our MTAs

% spfcheck example.com -v 0 -d tmp/zonedata.txt
domain     : example.com
ip         : 127.0.0.1
sender     : example.com
verdict    : fail
reason     : spf[0] -all
num_spf    : 1
num_dnsm   : 0
num_dnsq   : 2
num_dnsv   : 0
num_checks : 1
num_warn   : 0
num_error  : 0
duration   : 1
explanation: example.com: 127.0.0.1 is not one of our MTAs
```

`spfcheck` counts the number of dns mechanisms seen (dnsm), the number of
queries performed (dnsq) and the number of void dns queries seen (dnsv).
If the evaluation took more than `10` dns mechanisms, the verdict is modified
accordingly.

The `-h` allows for setting the EHLO domain name and defaults to given
`sender`.  Note that `spfcheck` only checks SPF for `sender`, so this is only
useful when checking the expansion of the `%{h}`-macro in a policy.

The `-i` flag is used to set sender's IP to either an IPv4 or an IPv6 address,
it defaults to `127.0.0.1` as an unlikely address to be authorized by anyone.
The goal is to go down the rabbit hole as far as possible and check the entire
nested SPF policy for given `sender`.

The `-r` flag can be used to print out some information, topics include:
- `v` the verdict and some statistics
- `s` the spf records seen and their authority information
- `e` the errors seen
- `w` the warnings seen
- `p` the prefixes collected
- `d` DNS information collected
- `a` the AST for the (first) SPF record
- `t` the tokens for the (first) SPF record

In case no `-r` flag is used, spfcheck will simply print out the verdict.

```txt
% spfcheck example.com -v 0 -r s --no-markdown
[0] example.com -- (example.com, noc@dns.icann.org)
    v=spf1 -all
```

Here, the SPF section lists all SPF records seen along with the authoritative
domain and its DNS admin email.

The `-v` flag controls the verbosity level of logging on stderr:
- 0 - no messages at all
- 1 - errors
- 2 - warnings
- 3 - notifications
- 4 - informational
- 5 - debug

```txt
% spfcheck example.com -v 5 --no-color
%spf[0]-ctx-debug:  > created context for example.com
%spf[0]-spf-note:   > spfcheck(example.com, 127.0.0.1, example.com)
%spf[0]-ipt-debug:  > ipt added {example.com, txt} -> "v=spf1 -all"
%spf[0]-ipt-debug:  > ipt added {example.com, txt} -> "8j5nfqld20zpcyr8xjw0ydcfq9rk8hgm"
%spf[0]-dns-info:   > DNS QUERY (1) txt example.com - ["8j5nfqld20zpcyr8xjw0ydcfq9rk8hgm", "v=spf1 -all"]
%spf[0]-spf-note:   > SPF (0): ["v=spf1 -all"]
%spf[0]-eval-info:  > spf[0] -all - matches

domain     : example.com
ip         : 127.0.0.1
sender     : example.com
verdict    : fail
reason     : spf[0] -all
num_spf    : 1
num_dnsm   : 0
num_dnsq   : 1
num_dnsv   : 0
num_checks : 1
num_warn   : 0
num_error  : 0
duration   : 1
explanation:
```

<!-- @MODULEDOC -->

## Installation

You can install `spfcheck` as an escript:

```bash
mix escript.install hex spfcheck
```

After installation, `~/.mix/escripts/spfcheck` invokes the escript.

Or use it in a project by adding `spfcheck` to the list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:spfcheck, "~> 0.1.0"}
  ]
end
```
