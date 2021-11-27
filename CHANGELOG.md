# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [unreleased]


### changed

- [x] prefixes are stored on exact match, not longest prefix match
- [x] "multiple entries" now means the exact same prefix was seen multiple times

### added

- [ ] "unreachable term"-warning when new prefix is subnet of an existing supernet
- [ ] "overlapping term"-warning when new prefix is supernet of an existing subnet
- [ ] "inconsistent qualifiers" for overlapping prefixes
- [ ] add debug logging during context creation
- [ ] add flags to customize title & author in markdown's metadata
- [ ] add flag to just create a dot-file that visualizes the domain's SPF (?)


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
