# Spfcheck


[![Test](https://github.com/hertogp/spfcheck/actions/workflows/elixir.yml/badge.svg)](https://github.com/hertogp/spfcheck/actions/workflows/elixir.yml)
[![Module Version](https://img.shields.io/hexpm/v/spfcheck.svg)](https://hex.pm/packages/spfcheck)
[![Hex Docs](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://hexdocs.pm/spfcheck/)
[![Last Updated](https://img.shields.io/github/last-commit/hertogp/spfcheck.svg)](https://github.com/hertogp/spfcheck/commits/main)
[![License](https://img.shields.io/hexpm/l/spfcheck?style=flat)](https://github.com/hertogp/spfcheck/blob/main/LICENSE.md)
[![Total Download](https://img.shields.io/hexpm/dt/spfcheck.svg)](https://hex.pm/packages/spfcheck)

<!-- @MODULEDOC -->

`spfcheck` is a command line tool to examine and debug SPF records.

## Usage

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
[`rfc7208 test suite`](http://www.open-spf.org/Test_Suite)
and should be reasonably
[`rfc7208`](https://www.rfc-editor.org/rfc/rfc7208.html) compliant.

```txt
% spfcheck example.com --no-color
example.com %spf[0]-ctx-info:   > sender is 'example.com'
example.com %spf[0]-ctx-info:   > local part set to 'postmaster'
example.com %spf[0]-ctx-info:   > domain part set to 'example.com'
example.com %spf[0]-ctx-info:   > ip is '127.0.0.1'
example.com %spf[0]-ctx-info:   > helo set to 'example.com'
example.com %spf[0]-ctx-info:   > DNS cache preloaded with 0 entrie(s)
example.com %spf[0]-ctx-info:   > verbosity level 4
example.com %spf[0]-ctx-info:   > created context for 'example.com'
example.com %spf[0]-spf-note:   > spfcheck(example.com, 127.0.0.1, example.com)
example.com %spf[0]-dns-info:   > DNS QUERY (1) txt example.com - ["8j5nfqld20zpcyr8xjw0ydcfq9rk8hgm", "v=spf1 -all"]
example.com %spf[0]-eval-note:  > spf[0] -all - matches
example.com %spf[0]-dns-info:   > DNS QUERY (2) soa example.com - [{"ns.icann.org", "noc.dns.icann.org", 2021111701, 7200, 3600, 1209600, 3600}]

domain     : example.com
ip         : 127.0.0.1
sender     : example.com
verdict    : fail
reason     : spf[0] -all
owner      : example.com
contact    : noc@dns.icann.org
num_spf    : 1
num_dnsm   : 0
num_dnsq   : 1
num_dnsv   : 0
num_checks : 1
num_warn   : 0
num_error  : 0
duration   : 0
explanation: 
```

## Batchmode

If no `sender` is given on the command line, `spfcheck` will read stdin for the
domains (and options) to check.  In this case, the verdict(s) are output on
stdout in csv-format as each domain is (sequentially) evaluated.

```txt
% cat senders.txt
example.com
me@example.net -i 1.2.3.4

% cat domains.txt | spfcheck -v 0
domain,ip,sender,verdict,reason,owner,contact,num_spf,num_dnsm,num_dnsq,num_dnsv,num_checks,num_warn,num_error,duration,explanation
"example.com","127.0.0.1","example.com",:fail,"spf[0] -all","example.com","noc@dns.icann.org",1,0,1,0,1,0,0,1,""
"example.net","1.2.3.4","me@example.net",:fail,"spf[0] -all","example.net","noc@dns.icann.org",1,0,1,0,1,0,0,0,""
```

## DNS flag

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
owner      : example.com
contact    : noc@dns.icann.org
num_spf    : 1
num_dnsm   : 0
num_dnsq   : 1
num_dnsv   : 0
num_checks : 1
num_warn   : 1
num_error  : 0
duration   : 0
explanation:


# Or using a file

% cat tmp/zonedata.txt
# comments are ignored as are empty lines

example.com TXT v=spf1 -all exp=why.%{d}
example.com TXT just another txt record
why.example.com TXT %{d}: %{i} is not one of our MTA's

% spfcheck example.com -v 0 -d tmp/zonedata.txt

domain     : example.com
ip         : 127.0.0.1
sender     : example.com
verdict    : fail
reason     : spf[0] -all
owner      : example.com
contact    : noc@dns.icann.org
num_spf    : 1
num_dnsm   : 0
num_dnsq   : 2
num_dnsv   : 0
num_checks : 1
num_warn   : 0
num_error  : 0
duration   : 1
explanation: example.com: 127.0.0.1 is not one of our MTA's
```

`spfcheck` counts the number of dns mechanisms seen (dnsm), the number of
queries performed (dnsq) and the number of void dns queries seen (dnsv).
If the evaluation took more than `10` dns mechanisms or saw more than `2`
void DNS lookups, the verdict is modified accordingly.  The soa queries
used to retrieve/find the owner and contact information are not included
in the dns counters.

## Helo flag

The `-h` allows for setting the EHLO domain name and defaults to given
`sender`.  Note that `spfcheck` only checks SPF for `sender`, so this is only
useful when checking the expansion of the `%{h}`-macro in a policy.

## Ip flag

The `-i` flag is used to set sender's IP to either an IPv4 or an IPv6 address,
it defaults to `127.0.0.1` as an unlikely address to be authorized by anyone.
The goal is to go down the rabbit hole as far as possible and check the entire
nested SPF policy for given `sender`.  Notes:
- if given an IPv4-mapped IPv6 address, the IPv4 address is extracted and used
- if given IP address is invalid, it defaults to 127.0.0.1
- the given ip may also be a prefix rather than a full address

```txt
% spfcheck example.com --no-color -i "::ffff:1.2.3.4"
example.com %spf[0]-ctx-info:   > sender is 'example.com'
example.com %spf[0]-ctx-info:   > local part set to 'postmaster'
example.com %spf[0]-ctx-info:   > domain part set to 'example.com'
example.com %spf[0]-ctx-info:   > ip is '1.2.3.4'
example.com %spf[0]-ctx-note:   > '1.2.3.4' was extracted from IPv4-mapped IPv6 address '::ffff:1.2.3.4'
example.com %spf[0]-ctx-info:   > helo set to 'example.com'
example.com %spf[0]-ctx-info:   > DNS cache preloaded with 0 entrie(s)
example.com %spf[0]-ctx-info:   > verbosity level 4
example.com %spf[0]-ctx-info:   > created context for 'example.com'
example.com %spf[0]-spf-note:   > spfcheck(example.com, 1.2.3.4, example.com)
example.com %spf[0]-dns-info:   > DNS QUERY (1) txt example.com - ["8j5nfqld20zpcyr8xjw0ydcfq9rk8hgm", "v=spf1 -all"]
example.com %spf[0]-eval-note:  > spf[0] -all - matches
example.com %spf[0]-dns-info:   > DNS QUERY (2) soa example.com - [{"ns.icann.org", "noc.dns.icann.org", 2021111701, 7200, 3600, 1209600, 3600}]

domain     : example.com
ip         : 1.2.3.4
sender     : example.com
verdict    : fail
reason     : spf[0] -all
owner      : example.com
contact    : noc@dns.icann.org
num_spf    : 1
num_dnsm   : 0
num_dnsq   : 1
num_dnsv   : 0
num_checks : 1
num_warn   : 0
num_error  : 0
duration   : 0
explanation:

# or check for some prefix

% spfcheck example.com -i 1.1.255.0/24 -d "example.com txt v=spf1 ip4:1.1.0.0/16 -all" --no-color
example.com %spf[0]-ctx-info:   > sender is 'example.com'
example.com %spf[0]-ctx-info:   > local part set to 'postmaster'
example.com %spf[0]-ctx-info:   > domain part set to 'example.com'
example.com %spf[0]-ctx-info:   > ip is '1.1.255.0/24'
example.com %spf[0]-ctx-info:   > helo set to 'example.com'
example.com %spf[0]-ctx-info:   > DNS cache preloaded with 1 entrie(s)
example.com %spf[0]-ctx-info:   > verbosity level 4
example.com %spf[0]-ctx-info:   > created context for 'example.com'
example.com %spf[0]-spf-note:   > spfcheck(example.com, 1.1.255.0/24, example.com)
example.com %spf[0]-dns-info:   > DNS QUERY (1) [cache] txt example.com - ["v=spf1 ip4:1.1.0.0/16 -all"]
example.com %spf[0]-eval-note:  > spf[0] ip4:1.1.0.0/16 - matches 1.1.255.0/24
example.com %spf[0]-dns-info:   > DNS QUERY (2) soa example.com - [{"ns.icann.org", "noc.dns.icann.org", 2021111701, 7200, 3600, 1209600, 3600}]

domain     : example.com
ip         : 1.1.255.0/24
sender     : example.com
verdict    : pass
reason     : spf[0] ip4:1.1.0.0/16
owner      : example.com
contact    : noc@dns.icann.org
num_spf    : 1
num_dnsm   : 0
num_dnsq   : 1
num_dnsv   : 0
num_checks : 1
num_warn   : 0
num_error  : 0
duration   : 0
explanation: 
```

## No color

The `--no-color` flag disables the use of colors in log messages, which is
better when redirecting logging to a file.

For example:

```txt
%cat tmp/domains.txt
example.com
me@example.net -i 1.2.3.4

% cat tmp/domains.txt | spfcheck -v 5 --no-color 2>tmp/log.txt > tmp/checked.csv
% cat tmp/log.txt
example.com %spf[0]-ctx-info:   > sender is 'example.com'
example.com %spf[0]-ctx-info:   > local part set to 'postmaster'
example.com %spf[0]-ctx-info:   > domain part set to 'example.com'
example.com %spf[0]-ctx-info:   > ip is '127.0.0.1'
example.com %spf[0]-ctx-debug:  > atype set to 'a'
example.com %spf[0]-ctx-info:   > helo set to 'example.com'
example.com %spf[0]-ctx-debug:  > helo defaults to sender value
example.com %spf[0]-ctx-info:   > DNS cache preloaded with 0 entrie(s)
example.com %spf[0]-ctx-info:   > verbosity level 5
example.com %spf[0]-ctx-debug:  > DNS timeout set to 2000
example.com %spf[0]-ctx-debug:  > max DNS mechanisms set to 10
example.com %spf[0]-ctx-debug:  > max void DNS lookups set to 2
example.com %spf[0]-ctx-debug:  > verdict defaults to 'neutral'
example.com %spf[0]-ctx-info:   > created context for 'example.com'
example.com %spf[0]-spf-note:   > spfcheck(example.com, 127.0.0.1, example.com)
example.com %spf[0]-dns-debug:  > added {example.com, txt} -> "v=spf1 -all"
example.com %spf[0]-dns-debug:  > added {example.com, txt} -> "8j5nfqld20zpcyr8xjw0ydcfq9rk8hgm"
example.com %spf[0]-dns-info:   > DNS QUERY (1) txt example.com - ["8j5nfqld20zpcyr8xjw0ydcfq9rk8hgm", "v=spf1 -all"]
example.com %spf[0]-eval-note:  > spf[0] -all - matches
example.com %spf[0]-dns-debug:  > added {example.com, soa} -> {"ns.icann.org", "noc.dns.icann.org", 2021111701, 7200, 3600, 1209600, 3600}
example.com %spf[0]-dns-info:   > DNS QUERY (2) soa example.com - [{"ns.icann.org", "noc.dns.icann.org", 2021111701, 7200, 3600, 1209600, 3600}]
example.net %spf[0]-ctx-info:   > sender is 'me@example.net'
example.net %spf[0]-ctx-info:   > local part set to 'me'
example.net %spf[0]-ctx-info:   > domain part set to 'example.net'
example.net %spf[0]-ctx-info:   > ip is '1.2.3.4'
example.net %spf[0]-ctx-debug:  > atype set to 'a'
example.net %spf[0]-ctx-info:   > helo set to 'me@example.net'
example.net %spf[0]-ctx-debug:  > helo defaults to sender value
example.net %spf[0]-ctx-info:   > DNS cache preloaded with 0 entrie(s)
example.net %spf[0]-ctx-info:   > verbosity level 5
example.net %spf[0]-ctx-debug:  > DNS timeout set to 2000
example.net %spf[0]-ctx-debug:  > max DNS mechanisms set to 10
example.net %spf[0]-ctx-debug:  > max void DNS lookups set to 2
example.net %spf[0]-ctx-debug:  > verdict defaults to 'neutral'
example.net %spf[0]-ctx-info:   > created context for 'example.net'
example.net %spf[0]-spf-note:   > spfcheck(example.net, 1.2.3.4, me@example.net)
example.net %spf[0]-dns-debug:  > added {example.net, txt} -> "5fpl1ghm7scnth0907z0pft8c79lvc8t"
example.net %spf[0]-dns-debug:  > added {example.net, txt} -> "v=spf1 -all"
example.net %spf[0]-dns-info:   > DNS QUERY (1) txt example.net - ["v=spf1 -all", "5fpl1ghm7scnth0907z0pft8c79lvc8t"]
example.net %spf[0]-eval-note:  > spf[0] -all - matches
example.net %spf[0]-dns-debug:  > added {example.net, soa} -> {"ns.icann.org", "noc.dns.icann.org", 2021111701, 7200, 3600, 1209600, 3600}
example.net %spf[0]-dns-info:   > DNS QUERY (2) soa example.net - [{"ns.icann.org", "noc.dns.icann.org", 2021111701, 7200, 3600, 1209600, 3600}]
```

## Report flag

The `-r` flag can be used to print out some information, topics include:
- `v` the verdict and some statistics
- `s` the spf records seen and their authority information
- `e` the errors seen
- `w` the warnings seen
- `p` the prefixes collected
- `d` DNS information collected
- `a` the AST for the (first) SPF record
- `t` the tokens for the (last) SPF record seen

In case no `-r` flag is used, spfcheck will simply print out the verdict.

```txt
% spfcheck example.com -v 0 -r s --no-markdown
[0] example.com -- (example.com, noc@dns.icann.org)
    v=spf1 -all
```

Here, the SPF section lists all SPF records seen along with the authoritative
domain and its DNS admin email.

## Verbosity flag

The `-v` flag controls the verbosity level of logging on stderr:
- 0 - no messages at all
- 1 - errors
- 2 - warnings
- 3 - notifications
- 4 - informational
- 5 - debug

```txt
% spfcheck example.com -v 2 --no-color -d "example.com txt v=spf1 a -a/24 mx +all"  
example.com %spf[0]-parse-warn: > usage of spf[0] +all is not advisable
example.com %spf[0]-ipt-warn:   > spf[0] -a/24 - overlaps with more specific spf[0] a
example.com %spf[0]-ipt-warn:   > spf[0] -a/24 - inconsistent with more specific spf[0] a
example.com %spf[0]-eval-warn:  > spf[0] mx - unusable due to null MX for example.com

domain     : example.com
ip         : 127.0.0.1
sender     : example.com
verdict    : pass
reason     : spf[0] +all
owner      : example.com
contact    : noc@dns.icann.org
num_spf    : 1
num_dnsm   : 3
num_dnsq   : 4
num_dnsv   : 0
num_checks : 4
num_warn   : 4
num_error  : 0
duration   : 1
explanation:
```

## Width flag

Finally, the `-w` flag can be used to control the width used when printing
information of certain topics.  Primarily meant so a markdown formatted report
can be easily converted to pdf.  Default value is 60, but you can make it as
wide as necessary.

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
    {:spfcheck, "~> 0.4.0"}
  ]
end
```
