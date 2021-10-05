// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/vulndb/report"
	"gopkg.in/yaml.v2"
)

var indexTemplate = template.Must(template.New("index").Parse(`<html>
<body>
	<h1>Go Vulnerability Database</h1>
	<ul>
		{{range .Vulns}}<li><a href="{{.}}.html">{{.}}</a></li>{{end}}
	</ul>
	<h2>Packages</h2>
	<ul>
		{{range .Packages}}<li><a href="{{.}}.html">{{.}}</a></li>{{end}}
	</ul>
</body>
</html>`))
var packageIndexTemplate = template.Must(template.New("package-index").Parse(`<html>
<body>
	<h1>{{.Name}} Vulnerabilities</h1>
	<ul>
		{{range .Vulns}}<li><a href="{{.}}.html">{{.}}</a></li>{{end}}
	</ul>
</body>
</html>`))
var vulnTemplate = template.Must(template.New("vuln").Parse(`<html>
<body>
    <h1>{{.Name}}</h1>
    {{if .Vuln.Severity}}<p><b>Severity: </b>{{.Vuln.Severity}}</p>{{end}}
    {{if .Vuln.OS}}<p><b>Affected Operating Systems: </b>{{.Vuln.OS}}</p>{{end}}
    {{if .Vuln.Arch}}<p><b>Affected Architectures: </b>{{.Vuln.Arch}}</p>{{end}}
	<p>{{.Vuln.Description}}</p>
	{{if .Vuln.Credit}}<p><b>Credit: </b>{{.Vuln.Credit}}</p>{{end}}
	{{if .Vuln.CVE}}<p><b>CVE: </b>{{.Vuln.CVE}}</p>{{end}}

    <h2>Affected Packages</h2>
    <table>
        <tr>
            <th>Package</th>
            <th>Introduced</th>
            <th>Fixed</th>
            <th>Symbols</th>
        </tr>
        <tr>
            <td><code>{{.Vuln.Package}}</code></td>
            {{if not .Vuln.Versions}}<td colspan="2" style="text-align: center">All available versions are vulnerable</td>{{else}}
            {{range .Vuln.Versions}}
            <td style="text-align: center">{{.Introduced}}</td>
            <td style="text-align: center">{{.Fixed}}</td>
            {{end}}
            {{end}}
            <td>
                <ul>
                    {{range .Vuln.Symbols}}<li><code>{{.}}</code></li>{{end}}
                </ul>
            </td>
        </tr>
        {{range .Vuln.AdditionalPackages}}
        <tr>
            <td><code>{{.Package}}</code></td>
            {{if not .Versions}}<td colspan="2" style="text-align: center">All available versions are vulnerable</td>{{else}}
            {{range .Versions}}
            <td style="text-align: center">{{.Introduced}}</td>
            <td style="text-align: center">{{.Fixed}}</td>
            {{end}}
            {{end}}
            <td>
                <ul>
                    {{range .Symbols}}<li><code>{{.}}</code></li>{{end}}
                </ul>
            </td>
        </tr>
        {{end}}
    </table>

	<h2>Context</h2>
	{{if .Vuln.Links.Commit}}<p><b>Commit: </b><a href="{{.Vuln.Links.Commit}}">{{.Vuln.Links.Commit}}</a></p>{{end}}
	{{if .Vuln.Links.PR}}<p><b>PR: </b><a href="{{.Vuln.Links.PR}}">{{.Vuln.Links.PR}}</a></p>{{end}}
	{{if .Vuln.Links.Context}}<p><b>Additional links:</b><ul>{{range .Vuln.Links.Context}}<li><a href="{{.}}">{{.}}</a></li>{{end}}</ul></p>{{end}}
</body>
</html>`))

func generateWebsite(vulns map[string]report.Report, htmlDir string) error {
	index := map[string][]string{}
	var vulnNames []string
	for name, vuln := range vulns {
		index[vuln.Package] = append(index[vuln.Package], name)
		for _, additional := range vuln.AdditionalPackages {
			index[additional.Package] = append(index[additional.Package], name)
		}
		vulnNames = append(vulnNames, name)

		filename := filepath.Join(htmlDir, name+".html")
		file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
		if err != nil {
			return err
		}
		defer file.Close()
		err = vulnTemplate.Execute(file, struct {
			Name string
			Vuln report.Report
		}{
			Name: name,
			Vuln: vuln,
		})
		if err != nil {
			return err
		}
	}

	for p, vulns := range index {
		filename := filepath.Join(htmlDir, p+".html")
		if err := os.MkdirAll(strings.TrimSuffix(filename, filepath.Base(filename)), 0755); err != nil {
			return err
		}
		file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
		if err != nil {
			return err
		}
		defer file.Close()
		err = packageIndexTemplate.Execute(file, struct {
			Name  string
			Vulns []string
		}{
			Name:  p,
			Vulns: vulns,
		})
		if err != nil {
			return err
		}
	}

	var packageNames []string
	for name := range index {
		packageNames = append(packageNames, name)
	}

	sort.Strings(packageNames)
	sort.Strings(vulnNames)
	file, err := os.OpenFile(filepath.Join(htmlDir, "index.html"), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer file.Close()
	err = indexTemplate.Execute(file, struct {
		Vulns    []string
		Packages []string
	}{
		Vulns:    vulnNames,
		Packages: packageNames,
	})
	if err != nil {
		return err
	}
	return nil
}

func fail(why string) {
	fmt.Fprintln(os.Stderr, why)
	os.Exit(1)
}

func main() {
	yamlDir := flag.String("reports", "Directory containing yaml reports", "")
	htmlDir := flag.String("out", "Directory to write website to", "")
	flag.Parse()

	htmlVulns := map[string]report.Report{}
	yamlFiles, err := ioutil.ReadDir(*yamlDir)
	if err != nil {
		fail(fmt.Sprintf("can't read %q: %s", *yamlDir, err))
	}
	for _, f := range yamlFiles {
		if !strings.HasSuffix(f.Name(), ".yaml") {
			continue
		}
		content, err := ioutil.ReadFile(f.Name())
		if err != nil {
			fail(fmt.Sprintf("can't read %q: %s", f.Name(), err))
		}
		var vuln report.Report
		err = yaml.UnmarshalStrict(content, &vuln)
		if err != nil {
			fail(fmt.Sprintf("unable to unmarshal %q: %s", f.Name(), err))
		}
		if lints := vuln.Lint(); len(lints) > 0 {
			fmt.Fprintf(os.Stderr, "invalid vulnerability file %q:\n", os.Args[1])
			for _, lint := range lints {
				fmt.Fprintf(os.Stderr, "\t%s\n", lint)
			}
			os.Exit(1)
		}
		name := strings.TrimSuffix(filepath.Base(f.Name()), filepath.Ext(f.Name()))
		htmlVulns[name] = vuln
	}
	err = generateWebsite(htmlVulns, *htmlDir)
	if err != nil {
		fail(fmt.Sprintf("failed to generate website: %s", err))
	}
}
