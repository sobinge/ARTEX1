package server

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

type memoryTorPoolSettings struct {
	values map[string]string
	err    error
}

func (s *memoryTorPoolSettings) GetSetting(key string) (string, bool, error) {
	v, ok := s.values[key]
	return v, ok, s.err
}

func (s *memoryTorPoolSettings) InsertSettingIfAbsent(key, value string) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	if _, ok := s.values[key]; ok {
		return false, nil
	}
	s.values[key] = value
	return true, nil
}

func TestTorPoolEnvSeedsOnlyMissingSettings(t *testing.T) {
	store := &memoryTorPoolSettings{values: map[string]string{settingTorPoolOn: "false", settingTorPoolSize: "2", settingTorPoolUpstream: "saved:8080"}}
	env := map[string]string{
		"ARTEX_TOR_POOL_ENABLED": "true", "ARTEX_TOR_POOL_SIZE": "5",
		"ARTEX_TOR_POOL_DIR": "/var/lib/artex-tor", "ARTEX_TOR_POOL_BINARY": "/usr/sbin/tor",
		"ARTEX_TOR_POOL_SOCKS_BASE": "19050", "ARTEX_TOR_POOL_CONTROL_BASE": "19150",
		"ARTEX_TOR_POOL_UPSTREAM": "deployment:7897",
	}
	if err := bootstrapTorPoolEnv(store, func(key string) string { return env[key] }); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		settingTorPoolOn: "false", settingTorPoolSize: "2", settingTorPoolUpstream: "saved:8080",
		settingTorPoolDir: "/var/lib/artex-tor", settingTorBinary: "/usr/sbin/tor",
		settingTorPoolSocksBase: "19050", settingTorPoolControlBase: "19150",
	}
	if !reflect.DeepEqual(store.values, want) {
		t.Fatalf("saved user choices changed or defaults missing: got %#v", store.values)
	}
	if err := bootstrapTorPoolEnv(store, func(key string) string { return env[key] }); err != nil || !reflect.DeepEqual(store.values, want) {
		t.Fatalf("second boot changed settings: %#v, err=%v", store.values, err)
	}
}

func TestTorPoolEnvEmptyLeavesNativeInstallUnchanged(t *testing.T) {
	store := &memoryTorPoolSettings{values: map[string]string{}}
	if err := bootstrapTorPoolEnv(store, func(string) string { return "" }); err != nil || len(store.values) != 0 {
		t.Fatalf("empty environment seeded native defaults: %#v, err=%v", store.values, err)
	}
}

func TestTorPoolEnvRejectsInvalidWithoutPartialWrites(t *testing.T) {
	cases := []struct{ key, value string }{
		{"ARTEX_TOR_POOL_ENABLED", "sometimes"}, {"ARTEX_TOR_POOL_SIZE", "0"}, {"ARTEX_TOR_POOL_SIZE", "33"},
		{"ARTEX_TOR_POOL_SOCKS_BASE", "65535"}, {"ARTEX_TOR_POOL_CONTROL_BASE", "19051"},
		{"ARTEX_TOR_POOL_DIR", "relative/path"}, {"ARTEX_TOR_POOL_DIR", "/data\nSocksPort 0.0.0.0:9050"},
		{"ARTEX_TOR_POOL_BINARY", "./tor"}, {"ARTEX_TOR_POOL_UPSTREAM", "https://proxy:7897"},
		{"ARTEX_TOR_POOL_UPSTREAM", "proxy:0"}, {"ARTEX_TOR_POOL_UPSTREAM", "proxy:70000"},
	}
	for _, tc := range cases {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			env := map[string]string{"ARTEX_TOR_POOL_ENABLED": "true", "ARTEX_TOR_POOL_SIZE": "5", tc.key: tc.value}
			store := &memoryTorPoolSettings{values: map[string]string{}}
			if err := bootstrapTorPoolEnv(store, func(key string) string { return env[key] }); err == nil {
				t.Fatal("invalid deployment environment was accepted")
			}
			if len(store.values) != 0 {
				t.Fatalf("invalid environment partially persisted: %#v", store.values)
			}
		})
	}
}

func TestTorPoolEnvDatabaseReadFailureIsNotMissing(t *testing.T) {
	store := &memoryTorPoolSettings{values: map[string]string{}, err: errors.New("unavailable")}
	err := bootstrapTorPoolEnv(store, func(string) string { return "" })
	if err == nil || !strings.Contains(err.Error(), "unavailable") || len(store.values) != 0 {
		t.Fatalf("database failure was treated as missing: err=%v values=%v", err, store.values)
	}
}
