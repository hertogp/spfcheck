# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [unreleased]
-[x] output contact email for domain as part of verdict output and csv output
-[ ] warn for superfluous prefix lengths applicable mechanisms (i.e. /32 resp. /128)
-[ ] create dot-file that visualizes the records (?)
-[ ] preprend current domain to messages, so a redirect to a log file shows the domain
-[ ] add warning for ?all and/or +all
-[ ] donot output %Pfx{} structs in logging
-[ ] add --logfile flag where logs are csv-fields: "domain", mnemonic, "msg"

### Changed
- verdict output includes owner domain and contact (also in csv-output)

### Fixed
- url for rfc7208 test suite


## [v0.1.1] - 2021-11-20
- Fix url for License badge


## [v0.1.0] - 2021-11-20
- Initial public version
