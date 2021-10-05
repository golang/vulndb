The main section of the YAML contains high level information about the vulnerability

TODO(golang/vulndb#9): update to YAML format.
```
package = "github.com/example/module"
```
**required** `package` contains the import path of the vulnerable module.

```
description = """
A remote attacker can craft a message which causes a panic via nil pointer dereference if the field
[`Config.Parser`] is not initialized.
"""
```
**required** `description` contains a textual description of the vulnerability and its impact. This field can contain a subset of markdown markup, used to link to godoc documentation for methods/types in the vulnerable module (and/or other modules).

```
cve = "CVE-000-000"
```
**optional** `cve` contains a CVE number for the vulnerability, if one has been assigned.

```
credit = "A. Reporter"
```
**optional** `credit` contains credit for the person/organization that discovered/reported the vulnerability.

```
symbols = ["Parser.Parse"]
```
**optional** `symbols` contains an array of vulnerable symbols. If included only programs which use these symbols will be marked as vulnerable. If omitted any program which imports this module will be marked vulnerable.

```
[[versions]]
```
The `versions` sections of the YAML contain information about when the vulnerability was introduced, and when it was fixed. If the vulnerability is fixed in multiple major versions, then the YAML should contain multiple `versions` sections. If omitted it is assumed that _every_ version of the module is vulnerable.

```
introduced = "v0.0.1"
```
**optional** `introduced` contains the pseudo-version at which the vulnerability was introduced. If this field is omitted it is assumed that every version, from the initial commit, up to the `fixed` version is vulnerable.

```
fixed = "v4.0.0-20190408214815-ec0a89a131e3"
```
**optional** `fixed` contains the pseudo-version at which the vulnerability was fixed. If this field is omitted it is assumed that every version since the `introduced` version is vulnerable.

```
[[additional_packages]]
```
The `additional_packages` sections of the YAML contain information about additional packages impacted by the vulnerability. These may be other submodules which independently implement the same vulnerability, or alternate module names for the same module.

```
package = "gopkg.in/vuln-mod"
```
**optional** `package` contains the import path of the additionally vulnerable module.

```
symbols = ["Parser.Parse"]
```
**optional** `symbols` contains an array of vulnerable symbols. If included only programs which use these symbols will be marked as vulnerable. If omitted any program which imports this module will be marked vulnerable.

```
[[additional_packages.versions]]
```
The `additional_packages.versions` sections contain version ranges for each additional package, following the same semantics as the `versions` section.

```
[links]
```
The `links` section of the YAML contains further information about the vulnerability.

```
commit = "https://github.com/example/module/commit/abcd"
```
**optional*** `commit` contains a link to the commit which fixes the vulnerability.

```
pr = "https://github.com/example/module/pulls/123"
```
**optional** `pr` contains a link to the PR/CL which fixes the vulnerability.

```
context = ["https://github.com/example/module/issues/50"]
```
**optional** `context` contains an array of additional links which provide additional context about the vulnerability, i.e. GitHub issues, vulnerability reports, etc.

# Example

```
package = "github.com/example/module"
description = """A description of the vulnerability present in this module.

The description can contain newlines, and a limited set of markup.
"""
cve = "CVE-2021-3185"
credit = "John Smith"
symbols = ["Type.MethodA", "MethodB"]

[[versions]]
# The vulnerability is present in all versions up to
# version v0.2.0
fixed = "v0.2.0"

[[versions]]
# The vulnerability is present in all versions since
# version v0.2.5
introduced = "v0.2.5

[[additional_packages]]
# Major versions must be explicitly specified
package = "github.com/example/module/v2"
symbols = ["MethodB"]
[[additional_packages.versions]]
fixed = "v2.5.0"

[[additional_packages]]
package = "github.com/example/module/v3"
symbols = ["MethodB"]
[[additional_packages.versions]]
introduced = "v3.0.1"

[links]
commit = "https://github.com/example/module/commit/aabbccdd"
pr = "https://github.com/example/module/pull/10"
context = [
    "https://www.openwall.com/lists/oss-security/2016/11/03/1",
    "https://github.com/example/module/advisories/1"
]
```
