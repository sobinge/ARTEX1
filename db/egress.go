package db

import (
	"database/sql"
	"time"
)

// EgressRun is one audit row: which egress an agent run actually used and what
// exit IP it was observed on. This is the platform-side transparency record.
type EgressRun struct {
	ID             int64      `json:"id"`
	AgentKey       string     `json:"agent_key"`
	TaskID         *string    `json:"task_id"`
	ConversationID *int64     `json:"conversation_id"`
	Mode           string     `json:"mode"`
	EgressHint     string     `json:"egress_hint"`
	ExitIP         string     `json:"exit_ip"`
	IsTor          *bool      `json:"is_tor"`
	CircuitUser    string     `json:"circuit_user"`
	InboundKind    string     `json:"inbound_kind"`
	InboundTarget  string     `json:"inbound_target"`
	OriginHidden   *bool      `json:"origin_hidden"`
	StartedAt      time.Time  `json:"started_at"`
	EndedAt        *time.Time `json:"ended_at"`
}

// StartEgressRun inserts an open audit row and returns its id.
func (d *DB) StartEgressRun(agentKey, mode, hint string, taskID *string, convID *int64) (int64, error) {
	var id int64
	err := d.QueryRow(`INSERT INTO agent_egress_runs(agent_key,mode,egress_hint,task_id,conversation_id)
VALUES ($1,$2,NULLIF($3,''),$4,$5) RETURNING id`, agentKey, mode, hint, taskID, convID).Scan(&id)
	return id, err
}

// FinishEgressRun closes the row with the observed exit IP / Tor flag.
func (d *DB) FinishEgressRun(id int64, exitIP string, isTor bool, circuitUser string) error {
	_, err := d.Exec(`UPDATE agent_egress_runs SET exit_ip=NULLIF($2,''), is_tor=$3,
		circuit_user=NULLIF($4,''), ended_at=now() WHERE id=$1`, id, exitIP, isTor, circuitUser)
	return err
}

// ListEgressRuns returns recent runs for one agent (newest first).
func (d *DB) ListEgressRuns(agentKey string, limit int) ([]*EgressRun, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := d.Query(`SELECT id,agent_key,task_id,conversation_id,mode,
		COALESCE(egress_hint,''),COALESCE(exit_ip,''),is_tor,COALESCE(circuit_user,''),
		COALESCE(inbound_kind,''),COALESCE(inbound_target,''),origin_hidden,started_at,ended_at
		FROM agent_egress_runs WHERE agent_key=$1 ORDER BY id DESC LIMIT $2`, agentKey, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*EgressRun
	for rows.Next() {
		var r EgressRun
		var isTor, hidden sql.NullBool
		var ended sql.NullTime
		var taskID sql.NullString
		var convID sql.NullInt64
		if err := rows.Scan(&r.ID, &r.AgentKey, &taskID, &convID, &r.Mode, &r.EgressHint,
			&r.ExitIP, &isTor, &r.CircuitUser, &r.InboundKind, &r.InboundTarget, &hidden,
			&r.StartedAt, &ended); err != nil {
			return nil, err
		}
		if taskID.Valid {
			v := taskID.String
			r.TaskID = &v
		}
		if convID.Valid {
			v := convID.Int64
			r.ConversationID = &v
		}
		if isTor.Valid {
			v := isTor.Bool
			r.IsTor = &v
		}
		if hidden.Valid {
			v := hidden.Bool
			r.OriginHidden = &v
		}
		if ended.Valid {
			v := ended.Time
			r.EndedAt = &v
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}
