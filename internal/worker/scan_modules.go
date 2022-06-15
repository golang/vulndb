// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"golang.org/x/tools/go/packages"
	vulnc "golang.org/x/vuln/client"
	"golang.org/x/vuln/vulncheck"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/worker/log"
	"golang.org/x/vulndb/internal/worker/store"
)

// Selected repos under golang.org/x.
var modulesToScan = []string{
	"golang.org/x/build", "golang.org/x/crypto", "golang.org/x/exp/event", "golang.org/x/exp/vulncheck",
	"golang.org/x/image", "golang.org/x/mod", "golang.org/x/net", "golang.org/x/oauth2",
	//"golang.org/x/pkgsite", requires 1.18-aware tools
	"golang.org/x/playground", "golang.org/x/review", "golang.org/x/sync",
	"golang.org/x/sys", "golang.org/x/term", "golang.org/x/text", "golang.org/x/time",
	"golang.org/x/tools",
	// "golang.org/x/tools/gopls", requires 1.18-aware tools
	"golang.org/x/vuln", "golang.org/x/vulndb", "golang.org/x/website",
}

type scanError struct {
	err error
}

func (s scanError) Error() string {
	return s.err.Error()
}

func (s scanError) Unwrap() error {
	return s.err
}

// ScanModules scans a list of Go modules for vulnerabilities.
// It assumes the root of each repo is a module, and there are no nested modules.
func ScanModules(ctx context.Context, st store.Store, force bool) error {
	dbClient, err := vulnc.NewClient([]string{vulnDBURL}, vulnc.Options{})
	if err != nil {
		return err
	}
	for _, modulePath := range modulesToScan {
		// Scan the latest version, and the latest tagged version (if they differ).
		latest, err := latestVersion(ctx, modulePath)
		if err != nil {
			return err
		}
		if err := processModule(ctx, modulePath, latest, dbClient, st, force); err != nil {
			if errors.As(err, new(scanError)) {
				return err
			}
			// Otherwise, if the error was in the scanning itself, keep going.
		}
		latestTagged, err := latestTaggedVersion(ctx, modulePath)
		if err != nil {
			return err
		}
		if latestTagged != "" && latestTagged != latest {
			if err := processModule(ctx, modulePath, latestTagged, dbClient, st, force); err != nil {
				return err
			}
		}
	}
	return nil
}

func processModule(ctx context.Context, modulePath, version string, dbClient vulnc.Client, st store.Store, force bool) (err error) {
	defer derrors.Wrap(&err, "processModule(%q, %q)", modulePath, version)

	dbTime, err := vulnDBTime(ctx)
	if err != nil {
		return err
	}
	if !force {
		r, err := st.GetModuleScanRecord(ctx, modulePath, version, dbTime)
		if err != nil {
			return err
		}
		if r != nil {
			// Already done.
			log.Infof(ctx, "already scanned %s@%s at DB time %s", modulePath, version, dbTime)
			return nil
		}
	}
	res, err := scanModule(ctx, modulePath, version, dbClient)
	if err2 := createModuleScanRecord(ctx, st, modulePath, version, dbTime, res, err); err2 != nil {
		return err2
	}
	if err != nil {
		return scanError{err}
	}
	for _, v := range res.Vulns {
		log.Warningf(ctx, "module %s@%s is vulnerable to %s: package %s, symbol %s",
			modulePath, version, v.OSV.ID, v.PkgPath, v.Symbol)
	}
	return nil
}

func createModuleScanRecord(ctx context.Context, st store.Store, path, version string, dbTime time.Time, res *vulncheck.Result, err error) error {
	var errstr string
	var vulnIDs []string
	if err != nil {
		errstr = err.Error()
	} else {
		m := map[string]bool{}
		for _, v := range res.Vulns {
			m[v.OSV.ID] = true
		}
		for id := range m {
			vulnIDs = append(vulnIDs, id)
		}
		sort.Strings(vulnIDs)
	}

	return st.CreateModuleScanRecord(ctx, &store.ModuleScanRecord{
		Path:       path,
		Version:    version,
		DBTime:     dbTime,
		Error:      errstr,
		VulnIDs:    vulnIDs,
		FinishedAt: time.Now(),
	})
}

// scanRepo clones the given repo and analyzes it for vulnerabilities. If commit
// is "HEAD", the head commit is scanned. Otherwise, commit must be a hex string
// corresponding to a commit, and that commit is checked out and scanned.
func scanModule(ctx context.Context, modulePath, version string, dbClient vulnc.Client) (_ *vulncheck.Result, err error) {
	defer derrors.Wrap(&err, "scanModule(%q, %q)", modulePath, version)

	start := time.Now()
	defer func() { log.Infof(ctx, "scanned %s@%s in %.1fs", modulePath, version, time.Since(start).Seconds()) }()

	dir, err := os.MkdirTemp("", "scanModule")
	if err != nil {
		return nil, err
	}

	defer func() {
		err1 := os.RemoveAll(dir)
		if err == nil {
			err = err1
		}
	}()

	zipr, err := moduleZip(ctx, modulePath, version)
	if err != nil {
		return nil, err
	}
	if err := writeZip(zipr, dir, modulePath+"@"+version+"/"); err != nil {
		return nil, err
	}

	cfg := &packages.Config{
		Mode:  packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports | packages.NeedTypes | packages.NeedTypesSizes | packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps | packages.NeedModule,
		Tests: true,
		Dir:   dir, // filepath.Join(dir, modulePath+"@"+version,
	}
	pkgs, err := loadPackages(cfg, []string{"./..."})
	if err != nil {
		return nil, err
	}
	vcfg := &vulncheck.Config{Client: dbClient}
	return vulncheck.Source(ctx, vulncheck.Convert(pkgs), vcfg)
}

func loadPackages(cfg *packages.Config, patterns []string) ([]*packages.Package, error) {
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, err
	}
	if packages.PrintErrors(pkgs) > 0 {
		return nil, fmt.Errorf("packages contain errors")
	}
	return pkgs, nil
}

func writeZip(r *zip.Reader, destination, stripPrefix string) error {
	for _, f := range r.File {
		name := strings.TrimPrefix(f.Name, stripPrefix)
		fpath := filepath.Join(destination, name)
		if !strings.HasPrefix(fpath, filepath.Clean(destination)+string(os.PathSeparator)) {
			return fmt.Errorf("%s is an illegal filepath", fpath)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(fpath, os.ModePerm); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}
		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		if _, err := io.Copy(outFile, rc); err != nil {
			return err
		}
		if err := outFile.Close(); err != nil {
			return err
		}
		if err := rc.Close(); err != nil {
			return err
		}
	}
	return nil
}

// vulnDBTime returns the time that the vuln DB was last updated.
func vulnDBTime(ctx context.Context) (_ time.Time, err error) {
	// Until the vuln DB client supports this, use the update time
	// of the index file.
	defer derrors.Wrap(&err, "vulnDBTime")
	c, err := storage.NewClient(ctx)
	if err != nil {
		return time.Time{}, err
	}
	attrs, err := c.Bucket(vulnDBBucket).Object("index.json").Attrs(ctx)
	if err != nil {
		return time.Time{}, err
	}
	return attrs.Updated, nil
}
