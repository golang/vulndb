# Go Vulnerability Database generator version

This file tracks modifications to the OSV generation.

The `modified` timestamp of reports is set based on the timestamp
of the last commit affecting this file.

When making a change that affects the generator, add a new entry
to the changelog below (most recent first). Do not otherwise change
this file.

## Changelog

   * Started storing the OSV for all reports in `data/osv`.
     Database generation will use this data rather than the YAML,
     ensuring that we always detect modifications to the generated
     OSV when setting the `modified` timestamp. Recording this change
     here in the same commit that adds `data/osv` ensures modification
     times remain the same when we switch generation methods.

   * Changed `affected.package` to contain the module path
     rather than the package path.
