File importers-{DATE}.csv.gz contains a gzipped CSV file whose records
are module paths and their number of importers as of {DATE}.

Number of importers is the importer count of the most-imported package
of the module at the latest version known to the module proxy.

It is used as a *rough* signal of the reach of a module for purposes
of vulnerability prioritization.