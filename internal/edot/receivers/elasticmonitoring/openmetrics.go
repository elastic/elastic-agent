// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticmonitoring

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// formatOpenMetrics renders a slice of ScopeMetrics in the OpenMetrics text
// exposition format. It is intended for diagnostic logging — the output is
// substantially smaller than a JSON-reflected dump of the same data because
// metric metadata (description, unit, type) is emitted once per metric
// family rather than once per data point, and labels/values don't carry Go
// struct field names.
//
// Supported aggregation types: Sum, Gauge, Histogram (int64 and float64).
// Other aggregations are emitted as a single `# TYPE … unknown` comment so
// no metric silently disappears from the log.
//
// Non-default temporality (i.e. delta) is preserved via the synthetic
// `__temporality="delta"` label so a downstream reader can still distinguish
// it. All metrics seen in elastic-agent's internal telemetry today are
// cumulative, so in practice this label is never emitted.
func formatOpenMetrics(scopeMetrics []metricdata.ScopeMetrics) string {
	// Group by metric name across scopes. The OpenMetrics spec requires
	// HELP/TYPE/UNIT to appear at most once per metric family, and it's
	// also a significant size win: in receiver-per-stream the same metric
	// name (e.g. otelcol_exporter_sent_log_records) appears in dozens of
	// scopes — deduplicating the metadata saves ~80 bytes per scope.
	families := map[string][]metricInstance{}
	order := []string{}
	for _, sm := range scopeMetrics {
		scopeLabels := scopeAttributesToLabels(sm.Scope)
		for _, m := range sm.Metrics {
			if _, ok := families[m.Name]; !ok {
				order = append(order, m.Name)
			}
			families[m.Name] = append(families[m.Name], metricInstance{m, scopeLabels})
		}
	}

	var sb strings.Builder
	for _, name := range order {
		writeFamily(&sb, name, families[name])
	}
	sb.WriteString("# EOF\n")
	return sb.String()
}

func writeFamily(sb *strings.Builder, name string, instances []metricInstance) {
	// HELP/UNIT/TYPE come from the first instance — they're properties of
	// the metric definition, identical across scopes for the same name.
	first := instances[0].metric
	writeHelp(sb, name, first.Description)
	if first.Unit != "" {
		sb.WriteString("# UNIT ")
		sb.WriteString(name)
		sb.WriteByte(' ')
		sb.WriteString(first.Unit)
		sb.WriteByte('\n')
	}
	writeFamilyType(sb, name, first.Data)
	for _, inst := range instances {
		writePoints(sb, inst.metric, inst.scopeLabels)
	}
}

// metricInstance pairs a metric with the (already-formatted) scope labels
// that should be attached to each of its data points.
type metricInstance struct {
	metric      metricdata.Metrics
	scopeLabels []label
}

// writeFamilyType emits the # TYPE line based on the aggregation shape.
func writeFamilyType(sb *strings.Builder, name string, data metricdata.Aggregation) {
	switch d := data.(type) {
	case metricdata.Sum[int64]:
		writeSumType(sb, name, d.IsMonotonic)
	case metricdata.Sum[float64]:
		writeSumType(sb, name, d.IsMonotonic)
	case metricdata.Gauge[int64], metricdata.Gauge[float64]:
		writeType(sb, name, "gauge")
	case metricdata.Histogram[int64], metricdata.Histogram[float64]:
		writeType(sb, name, "histogram")
	default:
		writeType(sb, name, "unknown")
	}
}

func writePoints(sb *strings.Builder, m metricdata.Metrics, scopeLabels []label) {
	switch d := m.Data.(type) {
	case metricdata.Sum[int64]:
		writeSumPoints(sb, m.Name, d.DataPoints, d.Temporality, d.IsMonotonic, scopeLabels, formatInt64)
	case metricdata.Sum[float64]:
		writeSumPoints(sb, m.Name, d.DataPoints, d.Temporality, d.IsMonotonic, scopeLabels, formatFloat64)
	case metricdata.Gauge[int64]:
		for _, p := range d.DataPoints {
			writeSimplePoint(sb, m.Name, p.Attributes, scopeLabels, formatInt64(p.Value), p.Time, "")
		}
	case metricdata.Gauge[float64]:
		for _, p := range d.DataPoints {
			writeSimplePoint(sb, m.Name, p.Attributes, scopeLabels, formatFloat64(p.Value), p.Time, "")
		}
	case metricdata.Histogram[int64]:
		for _, p := range d.DataPoints {
			writeHistogramPoint(sb, m.Name, p.Attributes, scopeLabels, p.Bounds, p.BucketCounts, formatInt64(p.Sum), p.Count, p.Time, p.StartTime, d.Temporality)
		}
	case metricdata.Histogram[float64]:
		for _, p := range d.DataPoints {
			writeHistogramPoint(sb, m.Name, p.Attributes, scopeLabels, p.Bounds, p.BucketCounts, formatFloat64(p.Sum), p.Count, p.Time, p.StartTime, d.Temporality)
		}
	}
}

func writeSumType(sb *strings.Builder, name string, monotonic bool) {
	if monotonic {
		writeType(sb, name, "counter")
	} else {
		// OpenMetrics has no non-monotonic counter; gauge is the closest fit.
		writeType(sb, name, "gauge")
	}
}

func writeSumPoints[N int64 | float64](
	sb *strings.Builder,
	name string,
	points []metricdata.DataPoint[N],
	temporality metricdata.Temporality,
	monotonic bool,
	scopeLabels []label,
	fmtVal func(N) string,
) {
	extra := temporalityLabel(temporality)
	for _, p := range points {
		writeSimplePoint(sb, name, p.Attributes, scopeLabels, fmtVal(p.Value), p.Time, extra)
		// _created lines are only meaningful for cumulative monotonic counters.
		if monotonic && temporality == metricdata.CumulativeTemporality && !p.StartTime.IsZero() {
			writeCreated(sb, name, p.Attributes, scopeLabels, p.StartTime, extra)
		}
	}
}

func writeSimplePoint(
	sb *strings.Builder,
	name string,
	attrs attribute.Set,
	scopeLabels []label,
	value string,
	ts time.Time,
	extra string,
) {
	sb.WriteString(name)
	writeLabels(sb, scopeLabels, attrs, extra)
	sb.WriteByte(' ')
	sb.WriteString(value)
	if !ts.IsZero() {
		sb.WriteByte(' ')
		sb.WriteString(formatTimestamp(ts))
	}
	sb.WriteByte('\n')
}

func writeCreated(
	sb *strings.Builder,
	name string,
	attrs attribute.Set,
	scopeLabels []label,
	startTime time.Time,
	extra string,
) {
	sb.WriteString(name)
	sb.WriteString("_created")
	writeLabels(sb, scopeLabels, attrs, extra)
	sb.WriteByte(' ')
	sb.WriteString(formatTimestamp(startTime))
	sb.WriteByte('\n')
}

func writeHistogramPoint(
	sb *strings.Builder,
	name string,
	attrs attribute.Set,
	scopeLabels []label,
	bounds []float64,
	bucketCounts []uint64,
	sumStr string,
	count uint64,
	ts time.Time,
	startTime time.Time,
	temporality metricdata.Temporality,
) {
	extra := temporalityLabel(temporality)
	tsStr := ""
	if !ts.IsZero() {
		tsStr = formatTimestamp(ts)
	}

	// Cumulative bucket counts: OpenMetrics requires le-bounded cumulative buckets.
	var cumulative uint64
	for i, b := range bounds {
		if i < len(bucketCounts) {
			cumulative += bucketCounts[i]
		}
		writeHistogramBucket(sb, name, attrs, scopeLabels, extra, strconv.FormatFloat(b, 'g', -1, 64), cumulative, tsStr)
	}
	// +Inf bucket gets the rest.
	if len(bucketCounts) > len(bounds) {
		cumulative += bucketCounts[len(bounds)]
	}
	writeHistogramBucket(sb, name, attrs, scopeLabels, extra, "+Inf", cumulative, tsStr)

	// _sum and _count.
	writeNamedPoint(sb, name+"_sum", attrs, scopeLabels, extra, sumStr, tsStr)
	writeNamedPoint(sb, name+"_count", attrs, scopeLabels, extra, strconv.FormatUint(count, 10), tsStr)

	if temporality == metricdata.CumulativeTemporality && !startTime.IsZero() {
		writeCreated(sb, name, attrs, scopeLabels, startTime, extra)
	}
}

func writeHistogramBucket(
	sb *strings.Builder,
	name string,
	attrs attribute.Set,
	scopeLabels []label,
	extra string,
	le string,
	cumulativeCount uint64,
	tsStr string,
) {
	sb.WriteString(name)
	sb.WriteString("_bucket")
	writeLabels(sb, scopeLabels, attrs, joinExtra(extra, `le=`+quoteLabelValue(le)))
	sb.WriteByte(' ')
	sb.WriteString(strconv.FormatUint(cumulativeCount, 10))
	if tsStr != "" {
		sb.WriteByte(' ')
		sb.WriteString(tsStr)
	}
	sb.WriteByte('\n')
}

func writeNamedPoint(
	sb *strings.Builder,
	name string,
	attrs attribute.Set,
	scopeLabels []label,
	extra string,
	value string,
	tsStr string,
) {
	sb.WriteString(name)
	writeLabels(sb, scopeLabels, attrs, extra)
	sb.WriteByte(' ')
	sb.WriteString(value)
	if tsStr != "" {
		sb.WriteByte(' ')
		sb.WriteString(tsStr)
	}
	sb.WriteByte('\n')
}

func writeHelp(sb *strings.Builder, name, description string) {
	if description == "" {
		return
	}
	sb.WriteString("# HELP ")
	sb.WriteString(name)
	sb.WriteByte(' ')
	sb.WriteString(escapeHelp(description))
	sb.WriteByte('\n')
}

func writeType(sb *strings.Builder, name, t string) {
	sb.WriteString("# TYPE ")
	sb.WriteString(name)
	sb.WriteByte(' ')
	sb.WriteString(t)
	sb.WriteByte('\n')
}

// label is a sanitized (name, quoted-value) pair carried so scope attributes
// can be sanitized once and reused across every data point in a scope.
type label struct {
	name        string
	quotedValue string
}

func scopeAttributesToLabels(scope instrumentation.Scope) []label {
	attrs := scope.Attributes.ToSlice()
	labels := make([]label, 0, len(attrs))
	for _, kv := range attrs {
		labels = append(labels, label{
			name:        sanitizeLabelName(string(kv.Key)),
			quotedValue: quoteLabelValue(kv.Value.Emit()),
		})
	}
	sort.Slice(labels, func(i, j int) bool { return labels[i].name < labels[j].name })
	return labels
}

// writeLabels writes the label block `{name="value",...}`. Data-point
// attributes take precedence over scope attributes on key collision. extra
// is an already-formatted label fragment (e.g. `le="0.5"`) appended last.
func writeLabels(sb *strings.Builder, scopeLabels []label, attrs attribute.Set, extra string) {
	pointAttrs := attrs.ToSlice()
	pointLabels := make([]label, 0, len(pointAttrs))
	seen := make(map[string]struct{}, len(pointAttrs))
	for _, kv := range pointAttrs {
		name := sanitizeLabelName(string(kv.Key))
		pointLabels = append(pointLabels, label{
			name:        name,
			quotedValue: quoteLabelValue(kv.Value.Emit()),
		})
		seen[name] = struct{}{}
	}
	sort.Slice(pointLabels, func(i, j int) bool { return pointLabels[i].name < pointLabels[j].name })

	if len(pointLabels) == 0 && len(scopeLabels) == 0 && extra == "" {
		return
	}
	sb.WriteByte('{')
	first := true
	emit := func(name, quoted string) {
		if !first {
			sb.WriteByte(',')
		}
		first = false
		sb.WriteString(name)
		sb.WriteByte('=')
		sb.WriteString(quoted)
	}
	for _, l := range pointLabels {
		emit(l.name, l.quotedValue)
	}
	for _, l := range scopeLabels {
		if _, dup := seen[l.name]; dup {
			continue
		}
		emit(l.name, l.quotedValue)
	}
	if extra != "" {
		if !first {
			sb.WriteByte(',')
		}
		sb.WriteString(extra)
	}
	sb.WriteByte('}')
}

func temporalityLabel(t metricdata.Temporality) string {
	if t == metricdata.DeltaTemporality {
		return `__temporality="delta"`
	}
	return ""
}

func joinExtra(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "," + b
	}
}

func sanitizeLabelName(s string) string {
	if s == "" {
		return "_"
	}
	var b strings.Builder
	b.Grow(len(s))
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			if i == 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func quoteLabelValue(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func escapeHelp(s string) string {
	// HELP text may contain anything except newline (escaped) and backslash (escaped).
	if !strings.ContainsAny(s, "\n\\") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func formatInt64(v int64) string { return strconv.FormatInt(v, 10) }
func formatFloat64(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// formatTimestamp returns the timestamp as seconds since epoch with
// millisecond resolution — that's the precision the OTel SDK records and
// it's what Prometheus tooling expects.
func formatTimestamp(t time.Time) string {
	return strconv.FormatFloat(float64(t.UnixNano())/1e9, 'f', 3, 64)
}
