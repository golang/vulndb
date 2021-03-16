This repository contains a handful of prototypes for the Go vulnerability database,
as well as a initial set of vulnerability reports. Some of these packages can probably
be coalesced, but for now are easier to work on in a more segmented fashion.

* `reports` contains TOML security reports, the format is described in `format.md`
* `report` provides a package for parsing and linting TOML reports
* `osv` provides a package for generating OSV-style JSON vulnerability entries from a `report.Report`
* `client` contains a client for accesing HTTP/fs based vulnerability databases, as well as a minimal caching implementation
* `cmd/gendb` provides a tool for converting TOML reports into JSON database
* `cmd/genhtml` provides a tool for converting TOML reports into a HTML website
* `cmd/linter` provides a tool for linting individual reports
* `cmd/report2cve` provides a tool for converting TOML reports into JSON CVEs