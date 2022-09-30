// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package observe provides metric and tracing support for Go servers.
// It uses OpenTelemetry and the golang.org/x/exp/events package.
package observe

import (
	"context"
	"net/http"

	"golang.org/x/exp/event"
	"golang.org/x/vulndb/internal/derrors"

	mexporter "github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric"
	texporter "github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/trace"
	gcppropagator "github.com/GoogleCloudPlatform/opentelemetry-operations-go/propagator"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	eotel "golang.org/x/exp/event/otel"
)

// An Observer handles tracing and metrics exporting.
type Observer struct {
	ctx            context.Context
	tracerProvider *sdktrace.TracerProvider
	traceHandler   *eotel.TraceHandler
	metricHandler  *eotel.MetricHandler
	propagator     propagation.TextMapPropagator
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
	// Create exporter (collector embedded with the exporter).
	controller, err := mexporter.NewExportPipeline([]mexporter.Option{
		mexporter.WithProjectID(projectID),
	})
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		// Enable tracing if there is no incoming request, or if the incoming
		// request is sampled.
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())),
		sdktrace.WithBatcher(exporter))
	return &Observer{
		ctx:            ctx,
		tracerProvider: tp,
		traceHandler:   eotel.NewTraceHandler(tp.Tracer(serverName)),
		metricHandler:  eotel.NewMetricHandler(controller.Meter(serverName)),
		// The propagator extracts incoming trace IDs so that we can connect our trace spans
		// to the incoming ones constructed by Cloud Run.
		propagator: propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
			gcppropagator.New()),
	}, nil
}

// BeforeRequest should be called before a request is processed.
// otherHandler can be any event.Handler that should be added to the event exporter
// for the request.
func (o *Observer) BeforeRequest(r *http.Request, otherHandler event.Handler) *http.Request {
	exporter := event.NewExporter(eventHandler{o, otherHandler}, nil)
	ctx := event.WithExporter(r.Context(), exporter)
	ctx = o.propagator.Extract(ctx, propagation.HeaderCarrier(r.Header))
	return r.WithContext(ctx)

}

// AfterRequest should be called after each request.
func (o *Observer) AfterRequest() {
	o.tracerProvider.ForceFlush(o.ctx)
}

type eventHandler struct {
	o  *Observer
	eh event.Handler
}

// Event implements event.Handler.
func (h eventHandler) Event(ctx context.Context, ev *event.Event) context.Context {
	ctx = h.eh.Event(ctx, ev)
	ctx = h.o.traceHandler.Event(ctx, ev)
	return h.o.metricHandler.Event(ctx, ev)
}
