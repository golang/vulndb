// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package observe provides metric and tracing support for Go servers.
// It uses OpenTelemetry.
package observe

import (
	"context"
	"net/http"
	"strings"

	"golang.org/x/exp/event"
	"golang.org/x/vulndb/internal/derrors"

	mexporter "github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric"
	texporter "github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/trace"
	gcppropagator "github.com/GoogleCloudPlatform/opentelemetry-operations-go/propagator"
	"github.com/jba/metrics/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	tnoop "go.opentelemetry.io/otel/trace/noop"
)

// An Observer handles tracing and metrics exporting.
type Observer struct {
	ctx            context.Context
	tracerProvider *sdktrace.TracerProvider
	tracer         trace.Tracer
	propagator     propagation.TextMapPropagator

	// LogHandlerFunc is invoked in [Observer.Observe] to obtain an
	// [event.Handler] for logging to be added to the [event.Exporter] in
	// addition to the tracing and metrics handlers.
	LogHandlerFunc func(*http.Request) event.Handler
}

// NewObserver creates an Observer.
// The context is used to flush traces in AfterRequest, so it should be longer-lived
// than any request context.
// (We don't want to use the request context because we still want traces even if
// it is canceled or times out.)
func NewObserver(ctx context.Context, projectID, serverName string) (_ *Observer, err error) {
	defer derrors.Wrap(&err, "NewObserver(%q, %q)", projectID, serverName)

	exporter, err := texporter.New(texporter.WithProjectID(projectID))
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(
		// Enable tracing if there is no incoming request, or if the incoming
		// request is sampled.
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())),
		sdktrace.WithBatcher(exporter))

	// Create exporter.
	mex, err := mexporter.New(mexporter.WithProjectID(projectID))
	if err != nil {
		return nil, err
	}
	// Export all registered metrics except the runtime metrics.
	scope := instrumentation.Scope{Name: "vulndb/worker"}
	otel.Export(scope, mex, 0, func(name string) bool {
		return !strings.HasPrefix(name, "runtime/")
	})

	return &Observer{
		ctx:            ctx,
		tracerProvider: tp,
		tracer:         tp.Tracer(serverName),
		// The propagator extracts incoming trace IDs so that we can connect our trace spans
		// to the incoming ones constructed by Cloud Run.
		propagator: propagation.NewCompositeTextMapPropagator(
			gcppropagator.CloudTraceOneWayPropagator{},
			propagation.TraceContext{},
			propagation.Baggage{}),
	}, nil
}

type key struct{}

// Observe adds metrics and tracing to an http.Handler.
func (o *Observer) Observe(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var otherHandler event.Handler
		if o.LogHandlerFunc != nil {
			otherHandler = o.LogHandlerFunc(r)
		}
		exporter := event.NewExporter(eventHandler{o, otherHandler}, nil)
		ctx := event.WithExporter(r.Context(), exporter)
		ctx = o.propagator.Extract(ctx, propagation.HeaderCarrier(r.Header))
		ctx = context.WithValue(ctx, key{}, o)
		defer o.tracerProvider.ForceFlush(o.ctx)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

type eventHandler struct {
	o  *Observer
	eh event.Handler
}

// Event implements event.Handler.
func (h eventHandler) Event(ctx context.Context, ev *event.Event) context.Context {
	if h.eh != nil {
		return h.eh.Event(ctx, ev)
	}
	return ctx
}

func Start(ctx context.Context, name string) (context.Context, trace.Span) {
	if obs, ok := ctx.Value(key{}).(*Observer); ok {
		return obs.tracer.Start(ctx, name)
	}
	return ctx, tnoop.Span{}
}
