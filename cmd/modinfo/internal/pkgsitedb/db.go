// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !plan9

// Package pkgsitedb provides functionality for connecting to the pkgsite
// database.
package pkgsitedb

import (
	"context"
	"database/sql"
	"fmt"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	smpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	_ "github.com/lib/pq"
)

type Config struct {
	User           string
	PasswordSecret string
	Password       string
	Host           string
	Port           string
	DBName         string
}

// Open creates a connection to the pkgsite database.
func Open(ctx context.Context, cfg Config) (_ *sql.DB, err error) {
	if cfg.Password == "" {
		var err error
		cfg.Password, err = getSecret(ctx, cfg.PasswordSecret)
		if err != nil {
			return nil, err
		}
	}

	connString := fmt.Sprintf(
		"user='%s' password='%s' host='%s' port=%s dbname='%s' sslmode='disable'",
		cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.DBName)
	db, err := sql.Open("postgres", connString)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, err
	}
	return db, nil
}

type Module struct {
	Path     string
	Packages []*Package
}

type Package struct {
	Path         string
	Version      string
	NumImporters int
}

func QueryModule(ctx context.Context, db *sql.DB, modulePath string) (*Module, error) {
	query := `
		SELECT package_path, version, imported_by_count
		FROM search_documents
		WHERE module_path = $1
		ORDER BY 3 DESC
	`
	rows, err := db.QueryContext(ctx, query, modulePath)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := &Module{Path: modulePath}
	for rows.Next() {
		var p Package
		if err := rows.Scan(&p.Path, &p.Version, &p.NumImporters); err != nil {
			return nil, err
		}
		m.Packages = append(m.Packages, &p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return m, nil
}

// getSecret retrieves a secret from the GCP Secret Manager.
// secretFullName should be of the form "projects/PROJECT/secrets/NAME".
func getSecret(ctx context.Context, secretFullName string) (_ string, err error) {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return "", err
	}
	defer client.Close()
	result, err := client.AccessSecretVersion(ctx, &smpb.AccessSecretVersionRequest{
		Name: secretFullName + "/versions/latest",
	})
	if err != nil {
		return "", err
	}
	return string(result.Payload.Data), nil
}
