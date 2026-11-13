package server

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestTaskAgentCacheRecoversAfterTorBootstrapAndRefusesAfterStop(t *testing.T) {
	// A closed SQL handle makes optional profile/agent lookups return their
	// documented defaults without requiring PostgreSQL or making LLM requests.
	sqlDB, err := sql.Open("pgx", "postgres://test@127.0.0.1/unused?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatal(err)
	}
	m := &Manager{dir: t.TempDir(), pg: &db.DB{DB: sqlDB}, egressStrict: true, torPoolEnabled: true}
	s := &Server{m: m, engine: &Engine{}, taskAgents: map[string]*taskAgentBundle{}}
	task := &Task{ID: "1"}
	before := s.agentsForTask(task)
	for _, binding := range before.egress {
		if binding.proxy != blackholeProxy {
			t.Fatalf("unready pool did not blackhole task: %+v", binding)
		}
	}
	m.torPool = newPoolForTest(t, 3)
	ready := s.agentsForTask(task)
	if ready == before {
		t.Fatal("task kept the cached blackhole bundle after Tor became ready")
	}
	for _, binding := range ready.egress {
		if !binding.tor || !strings.HasPrefix(binding.proxy, "socks5h://task-1:x@127.0.0.1:") {
			t.Fatalf("ready task did not use isolated Tor: %+v", binding)
		}
	}
	if stable := s.agentsForTask(task); stable != ready {
		t.Fatal("unchanged egress unnecessarily rebuilt task agents")
	}
	m.StopTorPool()
	stopped := s.agentsForTask(task)
	if stopped == ready {
		t.Fatal("task kept a stale Tor bundle after the pool stopped")
	}
	for _, binding := range stopped.egress {
		if binding.proxy != blackholeProxy || binding.tor {
			t.Fatalf("stopped pool did not restore blackhole task binding: %+v", binding)
		}
	}
}
