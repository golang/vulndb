# Copyright 2021 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# This Dockerfile expects the build context to be the repo root.

################################################################
FROM golang:1.17.3 AS builder
# If you change the Go version above, change the FROM line below as well.

# Set the working directory outside $GOPATH to ensure module mode is enabled.
WORKDIR /src

# Copy go.mod and go.sum into the container.
# If they don't change, which is the common case, then docker can
# cache this COPY and the subsequent RUN.
COPY go.mod go.sum checks.bash /

# Download the dependencies.
RUN go mod download

# Copy the repo from local machine into Docker client’s current working
# directory, so that we can use it to build the binary.
# See .dockerignore at the repo root for excluded files.
COPY . /src

# Build the binary.
RUN go build -mod=readonly ./cmd/worker

################################################################
FROM debian:stable-slim

LABEL maintainer="Go VulnDB Team <go-vulndb-team@google.com>"

# Copy CA certificates to prevent "x509: certificate signed by unknown authority" errors.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

WORKDIR app

COPY --from=builder src/worker      worker
COPY internal/worker/static         internal/worker/static

CMD ["./worker"]
