package buffer

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/itom-mini/agent/internal/collector"

	_ "modernc.org/sqlite"
)

// Buffer is a durable FIFO of metric samples for offline / retry delivery.
type Buffer interface {
	Append(sample collector.Sample) error
	PeekBatch(maxSize int) ([]Row, error)
	DeleteUpTo(lastID int64) error
	Count() (int, error)
	TrimToCap(maxRows int) (dropped int, err error)
	Close() error
}

// Row is one queued sample with its monotonic id.
type Row struct {
	ID     int64
	Sample collector.Sample
}

type sqliteBuffer struct {
	db      *sql.DB
	maxRows int
	log     *slog.Logger
}

// DefaultPath returns ~/.itom-agent/buffer.db
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".itom-agent", "buffer.db"), nil
}

// Open creates or opens the SQLite buffer at path.
func Open(path string, maxRows int, log *slog.Logger) (Buffer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", filepath.ToSlash(path))
	if err != nil {
		return nil, err
	}
	if _, err := db.ExecContext(context.Background(), `
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA busy_timeout=5000;
`); err != nil {
		_ = db.Close()
		return nil, err
	}
	schema := `
CREATE TABLE IF NOT EXISTS samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_samples_id ON samples(id);
`
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &sqliteBuffer{db: db, maxRows: maxRows, log: log}, nil
}

func (b *sqliteBuffer) Append(sample collector.Sample) error {
	payload, err := json.Marshal(sample)
	if err != nil {
		return err
	}
	_, err = b.db.Exec(`INSERT INTO samples (payload) VALUES (?)`, string(payload))
	if err != nil {
		return err
	}
	dropped, err := b.TrimToCap(b.maxRows)
	if err != nil {
		return err
	}
	if dropped > 0 && b.log != nil {
		b.log.Warn("buffer cap exceeded, dropped oldest samples", "dropped", dropped, "maxRows", b.maxRows)
	}
	return nil
}

func (b *sqliteBuffer) PeekBatch(maxSize int) ([]Row, error) {
	if maxSize <= 0 {
		return nil, nil
	}
	rows, err := b.db.Query(`SELECT id, payload FROM samples ORDER BY id ASC LIMIT ?`, maxSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Row, 0, maxSize)
	for rows.Next() {
		var id int64
		var payload string
		if err := rows.Scan(&id, &payload); err != nil {
			return nil, err
		}
		var s collector.Sample
		if err := json.Unmarshal([]byte(payload), &s); err != nil {
			return nil, err
		}
		out = append(out, Row{ID: id, Sample: s})
	}
	return out, rows.Err()
}

func (b *sqliteBuffer) DeleteUpTo(lastID int64) error {
	if lastID <= 0 {
		return nil
	}
	_, err := b.db.Exec(`DELETE FROM samples WHERE id <= ?`, lastID)
	return err
}

func (b *sqliteBuffer) Count() (int, error) {
	var n int
	err := b.db.QueryRow(`SELECT COUNT(*) FROM samples`).Scan(&n)
	return n, err
}

func (b *sqliteBuffer) TrimToCap(maxRows int) (int, error) {
	if maxRows <= 0 {
		return 0, errors.New("maxRows must be > 0")
	}
	var count int
	if err := b.db.QueryRow(`SELECT COUNT(*) FROM samples`).Scan(&count); err != nil {
		return 0, err
	}
	if count <= maxRows {
		return 0, nil
	}
	toDrop := count - maxRows
	res, err := b.db.Exec(`
DELETE FROM samples WHERE id IN (
  SELECT id FROM samples ORDER BY id ASC LIMIT ?
)`, toDrop)
	if err != nil {
		return 0, err
	}
	affected, _ := res.RowsAffected()
	return int(affected), nil
}

func (b *sqliteBuffer) Close() error {
	if b.db == nil {
		return nil
	}
	return b.db.Close()
}
