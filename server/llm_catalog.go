package server

import (
	"strings"
)

// ModelEntry is one row in the model picker. The provider's /models endpoint is
// authoritative for what exists, but several providers only list a subset there
// (DeepSeek currently exposes just deepseek-flash / deepseek-v4-pro while the
// gateway also routes v4-flash and vision variants). Entries not returned by the
// API are marked source=catalog so the UI can label them as unverified
// suggestions instead of pretending they were discovered.
type ModelEntry struct {
	ID              string   `json:"id"`
	Name            string   `json:"name,omitempty"`
	ContextWindow   int      `json:"context_window,omitempty"`
	MaxOutputTokens int      `json:"max_output_tokens,omitempty"`
	InputModalities []string `json:"input_modalities,omitempty"`
	EffortLevels    []string `json:"effort_levels,omitempty"`
	// Version is the concrete build behind an alias, e.g. deepseek-flash serves
	// DeepSeek-V4.1-Flash-1017. Operators need it because "v4.1" is a version, not
	// a model id — the API rejects deepseek-v4.1 outright.
	Version string `json:"version,omitempty"`
	// Latest marks the current generation for this provider.
	Latest bool `json:"latest,omitempty"`
	// Retired marks ids the provider still accepts but no longer serves with their
	// own weights (documented: served by the current Flash build).
	Retired bool `json:"retired,omitempty"`
	// Source is "api" (returned by /models) or "catalog" (local suggestion).
	Source string `json:"source"`
}

// modelCatalog holds curated entries per provider host. Only models we have a
// concrete reason to list (documented ids or ids observed in this deployment)
// belong here — an invented name wastes the operator's time.
var modelCatalog = map[string][]ModelEntry{
	"api.deepseek.com": {
		{ID: "deepseek-flash", Name: "DeepSeek-V4.1-Flash", Version: "V4.1-Flash-1017", Latest: true,
			ContextWindow: 1048576, MaxOutputTokens: 393216,
			InputModalities: []string{"text", "image"}, EffortLevels: []string{"low", "high", "max"}},
		{ID: "deepseek-v4-pro", Name: "DeepSeek-V4-Pro", Version: "V4-Pro-0813",
			ContextWindow: 1048576, MaxOutputTokens: 393216,
			InputModalities: []string{"text"}, EffortLevels: []string{"low", "high", "max"}},
		// Verified 2026-10-24: these ids return 200 and resolve to deepseek-flash,
		// so they are useful as compatibility aliases rather than distinct models.
		{ID: "deepseek-v4-flash", Name: "旧名，已退役（由 V4.1-Flash-1017 服务）", Retired: true,
			Version: "V4.1-Flash-1017", ContextWindow: 1048576},
		{ID: "deepseek-v4-flash-vision-exp", Name: "旧名，已退役（由 V4.1-Flash-1017 服务）", Retired: true,
			Version: "V4.1-Flash-1017", ContextWindow: 1048576, InputModalities: []string{"text", "image"}},
		{ID: "deepseek-chat", Name: "别名 → deepseek-flash（非思考语义）", Version: "V4.1-Flash-1017",
			ContextWindow: 1048576},
		{ID: "deepseek-reasoner", Name: "别名 → deepseek-flash（思考语义）", Version: "V4.1-Flash-1017",
			ContextWindow: 1048576},
	},
}

// catalogHost extracts the host used to look up the catalog.
func catalogHost(baseURL string) string {
	b := strings.TrimSpace(strings.ToLower(baseURL))
	if i := strings.Index(b, "://"); i >= 0 {
		b = b[i+3:]
	}
	if i := strings.IndexAny(b, "/"); i >= 0 {
		b = b[:i]
	}
	if i := strings.Index(b, ":"); i >= 0 {
		b = b[:i]
	}
	return b
}

// mergeModelEntries merges API-discovered ids with the curated catalog.
// API order is preserved (it reflects what the endpoint considers canonical) and
// duplicates are dropped by id. apiEntries carry any metadata the provider
// returned; catalog entries only fill the gaps.
func mergeModelEntries(apiEntries []ModelEntry, catalog []ModelEntry) []ModelEntry {
	seen := make(map[string]bool, len(apiEntries)+len(catalog))
	out := make([]ModelEntry, 0, len(apiEntries)+len(catalog))
	meta := make(map[string]ModelEntry, len(catalog))
	for _, c := range catalog {
		meta[c.ID] = c
	}
	for _, e := range apiEntries {
		if e.ID == "" || seen[e.ID] {
			continue
		}
		seen[e.ID] = true
		e.Source = "api"
		// /models never reports the concrete build or lifecycle state; take it
		// from the catalog so "deepseek-flash" can be shown as V4.1-Flash-1017.
		if c, ok := meta[e.ID]; ok {
			if e.Name == "" {
				e.Name = c.Name
			}
			e.Version = c.Version
			e.Latest = c.Latest
			e.Retired = c.Retired
			if len(e.EffortLevels) == 0 {
				e.EffortLevels = c.EffortLevels
			}
			if len(e.InputModalities) == 0 {
				e.InputModalities = c.InputModalities
			}
		}
		out = append(out, e)
	}
	for _, e := range catalog {
		if e.ID == "" || seen[e.ID] {
			continue
		}
		seen[e.ID] = true
		e.Source = "catalog"
		out = append(out, e)
	}
	return out
}

// catalogFor returns the curated entries for a base URL's host.
func catalogFor(baseURL string) []ModelEntry {
	return modelCatalog[catalogHost(baseURL)]
}

// modelIDs flattens entries to the plain id list older clients expect.
func modelIDs(entries []ModelEntry) []string {
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		ids = append(ids, e.ID)
	}
	return ids
}
