package server

import (
	"strings"
	"testing"
)

func TestCatalogHost(t *testing.T) {
	cases := map[string]string{
		"https://api.deepseek.com/v1/":       "api.deepseek.com",
		"https://api.deepseek.com/anthropic": "api.deepseek.com",
		"api.deepseek.com:443/v1":            "api.deepseek.com",
		"":                                   "",
	}
	for in, want := range cases {
		if got := catalogHost(in); got != want {
			t.Errorf("catalogHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCatalogForDeepSeekCoversFamily(t *testing.T) {
	got := catalogFor("https://api.deepseek.com/v1/")
	ids := map[string]bool{}
	for _, e := range got {
		ids[e.ID] = true
		if e.Name == "" {
			t.Errorf("catalog entry %s has no display name", e.ID)
		}
		if e.ContextWindow <= 0 {
			t.Errorf("catalog entry %s has no context window (picker cannot auto-fill)", e.ID)
		}
	}
	for _, want := range []string{
		"deepseek-v4-pro", "deepseek-flash", "deepseek-v4-flash",
		"deepseek-v4-flash-vision-exp", "deepseek-chat", "deepseek-reasoner",
	} {
		if !ids[want] {
			t.Errorf("catalog missing %s", want)
		}
	}
}

func TestCatalogForUnknownHostIsEmpty(t *testing.T) {
	if got := catalogFor("https://api.openai.com/v1"); len(got) != 0 {
		t.Fatalf("unexpected catalog for openai: %v", got)
	}
}

func TestMergeModelEntriesPrefersAPIMetadata(t *testing.T) {
	api := []ModelEntry{{ID: "deepseek-flash", Name: "DeepSeek-V4.1-Flash", ContextWindow: 1048576}}
	entries := mergeModelEntries(api, catalogFor("https://api.deepseek.com/v1"))
	if len(entries) == 0 {
		t.Fatal("empty merge")
	}
	if entries[0].Source != "api" {
		t.Fatalf("first entry source = %q", entries[0].Source)
	}
	// 去重：catalog 里同 id 的条目不能再出现
	n := 0
	for _, e := range entries {
		if e.ID == "deepseek-flash" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("duplicate deepseek-flash entries: %d", n)
	}
	// 追加的 catalog 条目必须标记来源
	for _, e := range entries[1:] {
		if e.Source != "catalog" {
			t.Fatalf("%s source = %q, want catalog", e.ID, e.Source)
		}
	}
}

func TestModelIDsKeepsOrder(t *testing.T) {
	entries := []ModelEntry{{ID: "b"}, {ID: "a"}}
	ids := modelIDs(entries)
	if strings.Join(ids, ",") != "b,a" {
		t.Fatalf("ids = %v", ids)
	}
}
