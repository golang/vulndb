// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package triage

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/idstr"
	"golang.org/x/vulndb/internal/pkgsite"
	"golang.org/x/vulndb/internal/stdlib"
	"golang.org/x/vulndb/internal/worker/log"
)

// stdlibReferenceDataKeywords are words found in the reference data URL that
// indicate the CVE is about the standard library or a Go x-repo owned by the
// Go team.
var stdlibReferenceDataKeywords = []string{
	"github.com/golang",
	"golang.org",
	// from https://groups.google.com/g/golang-announce.
	"golang-announce",
	// from https://groups.google.com/g/golang-nuts.
	"golang-nuts",
}

const unknownPath = "Path is unknown"

// RefersToGoModule reports whether the vuln refers to a Go module or package in its references.
func RefersToGoModule(ctx context.Context, v Vuln, pc *pkgsite.Client) (_ *Result, err error) {
	defer derrors.Wrap(&err, "triage.RefersToGoModule(%q)", v.SourceID())
	return refersToGoModule(ctx, v, pc)
}

type Result struct {
	ModulePath  string
	PackagePath string
	Reason      string
}

// gopkgHosts are hostnames for popular Go package websites.
var gopkgHosts = map[string]bool{
	"godoc.org":  true,
	"pkg.go.dev": true,
}

const snykIdentifier = "snyk.io/vuln/SNYK-GOLANG"

// nonGoModules are paths that return a 200 on pkg.go.dev, but do not contain
// meaningful Go code. However, these libraries often have CVEs that are
// false positive for a Go vuln.
var notGoModules = map[string]bool{
	"github.com/channelcat/sanic":                    true, // python library
	"github.com/rapid7/metasploit-framework":         true, // ruby library
	"github.com/tensorflow/tensorflow":               true, // python library
	"gitweb.gentoo.org/repo/gentoo.git":              true, // ebuild
	"qpid.apache.org":                                true, // C, python, & Java library
	"github.com/apache/airflow":                      true, // python
	"github.com/pyca/cryptography":                   true, // python
	"github.com/louislam/uptime-kuma":                true, // javscript
	"gitlab.nic.cz/knot/knot-resolver":               true, // C
	"github.com/ceph/ceph":                           true, // C
	"github.com/swoole/swoole-src":                   true, // php
	"git.sheetjs.com/sheetjs/sheetjs":                true, // javascript, typescript
	"github.com/glpi-project/glpi-agent":             true, // perl
	"gitlab.com/graphviz/graphviz":                   true, // C++
	"github.com/humhub/humhub":                       true, // php
	"github.com/TokTok/c-toxcore":                    true, // C
	"github.com/chamilo/chamilo-lms":                 true, // php
	"github.com/NationalSecurityAgency/ghidra":       true,
	"github.com/gongfuxiang/shopxo":                  true, // php
	"github.com/lemire/simdcomp":                     true, // C
	"github.com/Requarks/wiki":                       true, // nodejs
	"github.com/requarks/wiki":                       true, // nodejs
	"github.com/tendenci/tendenci":                   true, // python
	"github.com/ansible/ansible":                     true, // python
	"github.com/openshift/origin-server":             true, // ruby
	"github.com/jqueryfiletree/jqueryfiletree":       true, // javascript
	"github.com/liblouis/liblouis":                   true, // C
	"github.com/afaqurk/linux-dash":                  true, // javascript
	"github.com/erxes/erxes":                         true, // typescript
	"github.com/kvz/locutus":                         true, // javascript
	"github.com/locutusjs/locutus":                   true, // javascript
	"git.kernel.org/pub/scm/git/git.git":             true, // C
	"github.com/Alluxio/alluxio":                     true, // multiple (not Go)
	"github.com/DFIRKuiper/Kuiper":                   true, // python
	"github.com/JuliaLang/julia":                     true, // julia
	"github.com/apache/skywalking":                   true, // java
	"github.com/aptos-labs/aptos-core":               true, // rust
	"github.com/arangodb/arangodb":                   true, // C
	"github.com/bentoml/bentoml":                     true, // python
	"github.com/garden-io/garden":                    true, // typescript
	"github.com/git/git":                             true, // C
	"github.com/github/codeql-action":                true, // javascript
	"github.com/google/oss-fuzz":                     true, // python and typescript
	"github.com/grpc/grpc":                           true, // C
	"github.com/hyperledger/aries-cloudagent-python": true, // python
	"github.com/istio/envoy":                         true, // C++
	"github.com/libp2p/js-libp2p":                    true, // javascript
	"github.com/mozilla-mobile/mozilla-vpn-client":   true, // C
	"github.com/occlum/occlum":                       true, // C
	"github.com/openshift/origin-aggregated-logging": true, // multiple (not Go)
	"github.com/pygments/pygments":                   true, // python
	"github.com/raydac/netbeans-mmd-plugin":          true, // java
	"github.com/remarshal-project/remarshal":         true, // python
	"github.com/seancfoley/IPAddress":                true, // java
	"github.com/snapcore/snapcraft":                  true, // python
	"github.com/sourcegraph/cody":                    true, // typescript
	"github.com/unbit/uwsgi":                         true, // C++ and python
	"github.com/wkeyuan/DWSurvey":                    true, // java

	// vulnerability in tool, not importable package
	"github.com/grafana/grafana":          true,
	"github.com/sourcegraph/sourcegraph":  true,
	"gitlab.com/gitlab-org/gitlab-runner": true,
	"github.com/gravitational/teleport":   true,

	// not relevant for vulndb
	"github.com/drewxa/summer-tasks":          true, // hobby project
	"github.com/iamckn/eques":                 true, // exploit examples
	"github.com/offensive-security/exploitdb": true, // database, not a library or binary
	"github.com/1d8/publications":             true, // database

}

type Vuln interface {
	SourceID() string
	ReferenceURLs() []string
}

func refersToGoModule(ctx context.Context, v Vuln, pc *pkgsite.Client) (result *Result, err error) {
	defer func() {
		if err != nil {
			return
		}
		msg := fmt.Sprintf("Triage result for %s", v.SourceID())
		if result == nil {
			log.Debugf(ctx, "%s: not Go vuln", msg)
			return
		}
		log.Debugf(ctx, "%s: is Go vuln:\n%s", msg, result.Reason)
	}()
	for _, rurl := range v.ReferenceURLs() {
		if rurl == "" {
			continue
		}
		refURL, err := url.Parse(rurl)
		if err != nil {
			return nil, fmt.Errorf("url.Parse(%q): %v", rurl, err)
		}
		if strings.Contains(rurl, "golang.org/pkg") {
			mp := strings.TrimPrefix(refURL.Path, "/pkg/")
			return &Result{
				PackagePath: mp,
				ModulePath:  stdlib.ModulePath,
				Reason:      fmt.Sprintf("Reference data URL %q contains path %q", rurl, mp),
			}, nil
		}
		if gopkgHosts[refURL.Host] {
			mp := strings.TrimPrefix(refURL.Path, "/")
			if stdlib.Contains(mp) {
				return &Result{
					PackagePath: mp,
					ModulePath:  stdlib.ModulePath,
					Reason:      fmt.Sprintf("Reference data URL %q contains path %q", rurl, mp),
				}, nil
			}
			return &Result{
				ModulePath: mp,
				Reason:     fmt.Sprintf("Reference data URL %q contains path %q", rurl, mp),
			}, nil
		}
		modpaths := candidateModulePaths(refURL.Host + refURL.Path)
		for _, mp := range modpaths {
			if notGoModules[mp] {
				continue
			}
			known, err := pc.KnownModule(ctx, mp)
			if err != nil {
				return nil, err
			}
			if known {
				u := pc.URL() + "/" + mp
				return &Result{
					ModulePath: mp,
					Reason:     fmt.Sprintf("Reference data URL %q contains path %q; %q returned a status 200", rurl, mp, u),
				}, nil
			}
		}
	}

	// We didn't find a Go package or module path in the reference data. Check
	// secondary heuristics to see if this is a Go related CVE.
	for _, rurl := range v.ReferenceURLs() {
		// Example CVE containing snyk.io URL:
		// https://github.com/CVEProject/cvelist/blob/899bba20d62eb73e04d1841a5ff04cd6225e1618/2020/7xxx/CVE-2020-7668.json#L52.
		if strings.Contains(rurl, snykIdentifier) {
			return &Result{
				ModulePath: unknownPath,
				Reason:     fmt.Sprintf("Reference data URL %q contains %q", rurl, snykIdentifier),
			}, nil
		}

		// Check for reference data indicating that this is related to the Go
		// project.
		for _, k := range stdlibReferenceDataKeywords {
			if strings.Contains(rurl, k) {
				return &Result{
					ModulePath: stdlib.ModulePath,
					Reason:     fmt.Sprintf("Reference data URL %q contains %q", rurl, k),
				}, nil
			}
		}
	}
	return nil, nil
}

// AliasGHSAs returns the list of GHSAs that are possibly aliases for this
// vuln, based on the references.
func AliasGHSAs(v Vuln) []string {
	var ghsas []string
	for _, rurl := range v.ReferenceURLs() {
		if ghsa := idstr.FindGHSA(rurl); ghsa != "" {
			ghsas = append(ghsas, ghsa)
		}
	}
	return ghsas
}
