# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [unreleased]

- [ ] warn if address in a prefix is not the this-network address
- [ ] warn if policy snoops your sending address via macros

### fixed

- [x] leading zero's in ip4/6 prefix lengths is a syntax error
- [x] empty macro-string in an unknown modifier is actually legal
- [x] %{t} expands to timestamp

### changed

- [x] simplified the lexer, at the expense of the parser
- [x] removed dependency on nimble_parsec

### changed

- logs use uniform format: "term - message" format as much as possible


## [v0.6.0] - 2021-12-01

## added

- report option "g" to include a graphviz di-graph of the SPF policy
- warning when default '+'-qualifier is used in mechanisms

### changed

- a less confusing redundant-warning replaces the multiple-entries warning
- inconsistent warnings now report only the terms inconsistent with current term
- more consistent formatting of logging and verdict's reason


## [v0.5.0] - 2021-11-28

### added

- `--nameserver` flag to customize which nameservers to use via IPv4 and/or IPv6 addresses
- `--author` flag to set author information in markdown metadata
- `--title` flag to set title information in markdown metadata


## [v0.4.0] - 2021-11-27

### changed

- prefixes are stored on exact match, not longest prefix match
- multiple entries warning now means the exact same prefix was seen multiple times

### added

- unreachable-warning when new prefix is subnet of an existing supernet
- overlapping-warning when new prefix is supernet of an existing subnet
- inconsistent-warning for overlapping prefixes having different qualifiers
- notifications during context creation


## [v0.3.0] - 2021-11-26

### changed

- warning when exceeding 512 chars now shows offending SPF domain name
- "seen before"-warning changed into "multiple entries"-warning (less confusing)
- parser errors now correctly logged as :parse-errors instead of :eval-errors

### added

- warning about inconsistent qualifiers in case of multiple entries
- warning about mx used while domain has null MX record
- warning for superfluous prefix lengths (/32 resp. /128)
- warning for zero prefix lengths (/0)


## [v0.2.0] - 2021-11-21

### Changed

- verdict output includes owner domain and contact (also in csv-output)
- ipt logs show spf terms rather than their raw token
- logging to stderr now shows the domain in front, so redirecting stderr to a
  log file means the messages can be related to the domain being checked at
  that time.
- added warning when ?all or +all is used

### Fixed

- url for rfc7208 test suite
- use :dns (not :ipt) when logging dns additions to the cache


## [v0.1.1] - 2021-11-20

- Fix url for License badge

## [v0.1.0] - 2021-11-20

- Initial public version
