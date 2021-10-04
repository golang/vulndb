# The Go Vulnerability Database `golang.org/x/vulndb`

This repository is a prototype of the Go Vulnerability Database.
Read [the Draft Design](https://golang.org/design/draft-vulndb).

Neither the code, nor the data, nor the existence of this repository is to be
considered stable until an approved proposal.

**Important: vulnerability entries in this repository are represented in an
internal, unstable format that can and will change without notice.**

## Consuming database entries

Database clients must not rely on the contents of this repository. Instead, they
can access the tree of JSON entries rooted at

https://storage.googleapis.com/go-vulndb/

An `index.json` file maps module paths to last modified timestamps
([link](https://storage.googleapis.com/go-vulndb/index.json)).

For each module, a `NAME.json` file contains a list of vulnerability entries
([example](https://storage.googleapis.com/go-vulndb/golang.org/x/crypto.json)).

Note that this path and format are provisional and likely to change until an
approved proposal.

## Packages

Some of these packages can probably be coalesced, but for now are easier to work
on in a more segmented fashion.

* `report` provides a package for parsing and linting TOML reports
* `osv` provides a package for generating OSV-style JSON vulnerability entries
  from a `report.Report`
* `client` contains a client for accessing HTTP/fs based vulnerability
  databases, as well as a minimal caching implementation
* `cmd/dbdiff` provides a tool for comparing two different versions of the vulnerability database
* `cmd/gendb` provides a tool for converting TOML reports into JSON database
* `cmd/genhtml` provides a tool for converting TOML reports into a HTML website
* `cmd/linter` provides a tool for linting individual reports
* `cmd/report2cve` provides a tool for converting TOML reports into JSON CVEs

## License

Unless otherwise noted, the Go source files are distributed under
the BSD-style license found in the LICENSE file.

Database entries available at https://storage.googleapis.com/go-vulndb/ are
distributed under the terms of the
[CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/) license.
