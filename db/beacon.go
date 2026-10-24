package db

import (
	"database/sql"
	"time"
)

// BeaconChannel is one dead-drop channel. Both peers poll; nobody listens.
type BeaconChannel struct {
	ID         int64      `json:"id"`
	ChannelID  string     `json:"channel_id"`
	AgentKey   string     `json:"agent_key"`
	TaskID     *string    `json:"task_id"`
	Kind       string     `json:"kind"`
	Endpoint   string     `json:"endpoint"`
	LastSeqOut int64      `json:"last_seq_out"`
	LastSeqIn  int64      `json:"last_seq_in"`
	LastSeenAt *time.Time `json:"last_seen_at"`
	CreatedAt  time.Time  `json:"created_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

// BeaconMessage is one encrypted frame in either direction.
type BeaconMessage struct {
	ID         int64      `json:"id"`
	ChannelID  string     `json:"channel_id"`
	Direction  string     `json:"direction"`
	Seq        int64      `json:"seq"`
	Payload    []byte     `json:"-"`
	CreatedAt  time.Time  `json:"created_at"`
	ConsumedAt *time.Time `json:"consumed_at"`
}

// CreateBeaconChannel stores a new channel. psk must already be wrapped by the
// caller; this layer does not know how to protect it.
func (d *DB) CreateBeaconChannel(channelID, agentKey string, taskID *string, kind, endpoint string, psk []byte) error {
	_, err := d.Exec(`INSERT INTO beacon_channels(channel_id,agent_key,task_id,kind,endpoint,psk)
VALUES ($1,$2,$3,$4,$5,$6)`, channelID, agentKey, taskID, kind, endpoint, psk)
	return err
}

// ListBeaconChannels returns every channel, newest first.
func (d *DB) ListBeaconChannels() ([]*BeaconChannel, error) {
	rows, err := d.Query(`SELECT id,channel_id,agent_key,task_id,kind,endpoint,
		last_seq_out,last_seq_in,last_seen_at,created_at,revoked_at
		FROM beacon_channels ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*BeaconChannel
	for rows.Next() {
		var c BeaconChannel
		var task sql.NullString
		var seen, revoked sql.NullTime
		if err := rows.Scan(&c.ID, &c.ChannelID, &c.AgentKey, &task, &c.Kind, &c.Endpoint,
			&c.LastSeqOut, &c.LastSeqIn, &seen, &c.CreatedAt, &revoked); err != nil {
			return nil, err
		}
		if task.Valid {
			v := task.String
			c.TaskID = &v
		}
		if seen.Valid {
			v := seen.Time
			c.LastSeenAt = &v
		}
		if revoked.Valid {
			v := revoked.Time
			c.RevokedAt = &v
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

// GetBeaconChannel returns one channel plus its raw PSK (callers must never log it).
func (d *DB) GetBeaconChannel(channelID string) (*BeaconChannel, []byte, error) {
	var c BeaconChannel
	var task sql.NullString
	var seen, revoked sql.NullTime
	var psk []byte
	err := d.QueryRow(`SELECT id,channel_id,agent_key,task_id,kind,endpoint,
		last_seq_out,last_seq_in,last_seen_at,created_at,revoked_at,psk
		FROM beacon_channels WHERE channel_id=$1`, channelID).Scan(
		&c.ID, &c.ChannelID, &c.AgentKey, &task, &c.Kind, &c.Endpoint,
		&c.LastSeqOut, &c.LastSeqIn, &seen, &c.CreatedAt, &revoked, &psk)
	if err == sql.ErrNoRows {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if task.Valid {
		v := task.String
		c.TaskID = &v
	}
	if seen.Valid {
		v := seen.Time
		c.LastSeenAt = &v
	}
	if revoked.Valid {
		v := revoked.Time
		c.RevokedAt = &v
	}
	return &c, psk, nil
}

// RevokeBeaconChannel disables a channel; its messages stay for audit.
func (d *DB) RevokeBeaconChannel(channelID string) error {
	_, err := d.Exec(`UPDATE beacon_channels SET revoked_at=now() WHERE channel_id=$1 AND revoked_at IS NULL`, channelID)
	return err
}

// EnqueueBeaconMessage stores one frame and advances the direction's counter.
func (d *DB) EnqueueBeaconMessage(channelID, direction string, seq int64, frame []byte) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO beacon_messages(channel_id,direction,seq,payload)
VALUES ($1,$2,$3,$4)`, channelID, direction, seq, frame); err != nil {
		return err
	}
	col := "last_seq_in"
	if direction == "out" {
		col = "last_seq_out"
	}
	if _, err := tx.Exec(`UPDATE beacon_channels SET `+col+`=GREATEST(`+col+`,$2) WHERE channel_id=$1`, channelID, seq); err != nil {
		return err
	}
	return tx.Commit()
}

// TakePendingBeaconMessages returns unconsumed frames for a direction, oldest
// first, limited by n.
func (d *DB) TakePendingBeaconMessages(channelID, direction string, n int) ([]*BeaconMessage, error) {
	if n <= 0 || n > 100 {
		n = 20
	}
	rows, err := d.Query(`SELECT id,channel_id,direction,seq,payload,created_at,consumed_at
		FROM beacon_messages WHERE channel_id=$1 AND direction=$2 AND consumed_at IS NULL
		ORDER BY seq LIMIT $3`, channelID, direction, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*BeaconMessage
	for rows.Next() {
		var m BeaconMessage
		var consumed sql.NullTime
		if err := rows.Scan(&m.ID, &m.ChannelID, &m.Direction, &m.Seq, &m.Payload, &m.CreatedAt, &consumed); err != nil {
			return nil, err
		}
		if consumed.Valid {
			v := consumed.Time
			m.ConsumedAt = &v
		}
		out = append(out, &m)
	}
	return out, rows.Err()
}

// ConsumeBeaconMessages marks the given ids as delivered.
func (d *DB) ConsumeBeaconMessages(ids []int64) error {
	for _, id := range ids {
		if _, err := d.Exec(`UPDATE beacon_messages SET consumed_at=now() WHERE id=$1 AND consumed_at IS NULL`, id); err != nil {
			return err
		}
	}
	return nil
}

// AdvanceBeaconSeqIn records the highest inbound sequence accepted for a channel.
func (d *DB) AdvanceBeaconSeqIn(channelID string, seq int64) error {
	_, err := d.Exec(`UPDATE beacon_channels SET last_seq_in=GREATEST(last_seq_in,$2) WHERE channel_id=$1`, channelID, seq)
	return err
}

// TouchBeaconChannel records a heartbeat from the target side.
func (d *DB) TouchBeaconChannel(channelID string) error {
	_, err := d.Exec(`UPDATE beacon_channels SET last_seen_at=now() WHERE channel_id=$1`, channelID)
	return err
}
