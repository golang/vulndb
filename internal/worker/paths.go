// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"path"
	"regexp"
	"strings"

	"golang.org/x/mod/module"
)

// vcsHostWithThreeElementRepoName returns true when the hostname
// has three elements like hostname/account/project.
func vcsHostWithThreeElementRepoName(hostname string) bool {
	switch hostname {
	case
		"git.sr.ht",
		"gitea.com",
		"gitee.com",
		"gitlab.com",
		"hg.sr.ht",
		"bitbucket.org",
		"github.com",
		"golang.org",
		"launchpad.net":
		return true
	default:
		return false
	}
}

// negativePrefixPatterns is a list of glob patterns that describe prefixes of
//  potential module paths that are known not to be modules. These are turned
//  into regexps below and checked against each module path before calling
//  pkgsite. This can speed up triage because pkgsite requests are throttled.
var negativePrefixPatterns = []string{
	"*.blogspot.com",
	"*.blogspot.dk",
	"*.readthedocs.org",
	"*.slashdot.org",
	"advisories.mageia.org",
	"archives.neohapsis.com",
	"arstechnica.com/security",
	"blog.python.org",
	"blogs.oracle.com",
	"blogs.technet.com",
	"bugs.*",
	"bugzilla.*",
	"cert.uni-stuttgart.de/archive",
	"community.rapid7.com/community/*/blog",
	"cr.yp.to/talks",
	"crbug.com",
	"dev2dev.bea.com/pub/advisory",
	"developer.mozilla.org/docs",
	"developer.mozilla.org/en-US/docs",
	"docs.google.com",
	"docs.microsoft.com",
	"downloads.securityfocus.com/vulnerabilities",
	"drupal.org/node",
	"erpscan.com/advisories",
	"exchange.xforce.ibmcloud.com",
	"fedoranews.org",
	"ftp.caldera.com/pub/security",
	"ftp.netbsd.org/pub",
	"ftp.sco.com/pub",
	"github.com/*/*/blob",
	"github.com/*/*/commit",
	"github.com/*/*/issues",
	"groups.google.com",
	"helpx.adobe.com/security",
	"hg.openjdk.java.net",
	"ics-cert.us-cert.gov",
	"issues.apache.org",
	"issues.rpath.com",
	"java.net",
	"jira.*",
	"jvn.jp",
	"jvndb.jvn.jp",
	"krebsonsecurity.com",
	"labs.mwrinfosecurity.com/advisories",
	"lists.*/archive",
	"lists.*/archives",
	"lists.*/pipermail",
	"lists.apache.org",
	"lists.apple.com",
	"lists.debian.org",
	"lists.mysql.com",
	"lists.opensuse.org",
	"lists.ubuntu.com",
	"mail-archives.*",
	"mail.*.org/archive",
	"mail.*.org/archives",
	"mail.*/pipermail",
	"mailman.*.org/archives",
	"mailman.*.org/pipermail",
	"nodesecurity.io/advisories",
	"online.securityfocus.com/advisories",
	"openwall.com/lists",
	"oss.oracle.com/pipermail",
	"osvdb.org",
	"owncloud.org/about/security",
	"packetstormsecurity.com/files",
	"patches.sgi.com/support/free/security/advisories",
	"plus.google.com",
	"puppetlabs.com/security",
	"raw.github.com",
	"rhn.redhat.com/errata",
	"seclists.org",
	"secunia.com/advisories",
	"secunia.com/secunia_research",
	"security.e-matters.de/advisories",
	"security.gentoo.org/glsa",
	"securityreason.com/securityalert",
	"securityreason.com/securityalert/",
	"securityresponse.symantec.com",
	"securitytracker.com/alerts",
	"service.sap.com",
	"subversion.apache.org/security",
	"technet.microsoft.com/en-us/security",
	"technet.microsoft.com/security",
	"tools.cisco.com/security/center",
	"twitter.com",
	"ubuntu.com/usn",
	"usn.ubuntu.com",
	"www.adobe.com/support",
	"www.adobe.com/support/security",
	"www.atstake.com/research/advisories",
	"www.bugzilla.org/security",
	"www.cert.org/advisories",
	"www.ciac.org/ciac/bulletins",
	"www.cisco.com/warp/public/707",
	"www.coresecurity.com/advisories",
	"www.debian.org/security",
	"www.derkeiler.com/Mailing-Lists",
	"www.drupal.org/node",
	"www.exploit-db.com",
	"www.gentoo.org/security",
	"www.htbridge.com/advisory",
	"www.ibm.com/developerworks/java",
	"www.iss.net/security_center",
	"www.kb.cert.org",
	"www.kde.org/info/security",
	"www.kernel.org/pub",
	"www.kernel.org/pub/linux/kernel/v3*/ChangeLog*",
	"www.linux-mandrake.com/en/security",
	"www.linuxsecurity.com/advisories",
	"www.microsoft.com/technet/security",
	"www.mozilla.org/security",
	"www.netvigilance.com/advisory*",
	"www.novell.com/linux/security",
	"www.openwall.com/lists",
	"www.oracle.com/technetwork",
	"www.osvdb.org",
	"www.phpmyadmin.net/home_page/security",
	"www.portcullis-security.com/security-research-and-downloads",
	"www.postgresql.org/docs",
	"www.red-database-security.com/advisory",
	"www.redhat.com/archives",
	"www.redhat.com/support/errata",
	"www.samba.org/samba/security",
	"www.secunia.com/advisories",
	"www.securiteam.com/exploits",
	"www.securiteam.com/securitynews",
	"www.securiteam.com/unixfocus",
	"www.securiteam.com/windowsntfocus",
	"www.security-assessment.com/files",
	"www.securityfocus.com",
	"www.securitytracker.com",
	"www.sophos.com/en-us/support",
	"www.suse.com/support",
	"www.symantec.com/avcenter/security",
	"www.trustix.org/errata",
	"www.ubuntu.com/usn",
	"www.us-cert.gov/cas",
	"www.us-cert.gov/ncas",
	"www.us.debian.org/security",
	"www.vmware.com/security/advisories",
	"www.vupen.com/english/advisories",
	"www.wireshark.org/security",
	"www.zerodayinitiative.com/advisories",
	"xforce.iss.net/alerts",
	"zerodayinitiative.com/advisories",
}

var negativeRegexps []*regexp.Regexp

func init() {
	rep := strings.NewReplacer(".", `\.`, "*", `[^/]*`)
	for _, pat := range negativePrefixPatterns {
		r := "^" + rep.Replace(pat) + "($|/)"
		negativeRegexps = append(negativeRegexps, regexp.MustCompile(r))
	}
}

// matchesNegativeRegexp reports whether s matches any element of negativeRegexps.
func matchesNegativeRegexp(s string) bool {
	for _, nr := range negativeRegexps {
		if nr.MatchString(s) {
			return true
		}
	}
	return false
}

// candidateModulePaths returns the potential module paths that could contain
// the fullPath, from longest to shortest. It returns nil if no valid module
// paths can be constructed.
func candidateModulePaths(fullPath string) []string {
	if matchesNegativeRegexp(fullPath) {
		return nil
	}
	if stdlibContains(fullPath) {
		if err := module.CheckImportPath(fullPath); err != nil {
			return nil
		}
		return []string{"std"}
	}
	var r []string
	for p := fullPath; p != "." && p != "/"; p = path.Dir(p) {
		if err := module.CheckPath(p); err != nil {
			continue
		}
		r = append(r, p)
	}
	if len(r) == 0 {
		return nil
	}
	if !vcsHostWithThreeElementRepoName(r[len(r)-1]) {
		return r
	}
	if len(r) < 3 {
		return nil
	}
	return r[:len(r)-2]
}

// stdlibContains reports whether the given import path could be part of the Go standard library,
// by reporting whether the first component lacks a '.'.
func stdlibContains(path string) bool {
	if i := strings.IndexByte(path, '/'); i != -1 {
		path = path[:i]
	}
	return !strings.Contains(path, ".")
}
