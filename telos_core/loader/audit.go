package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"
)

const (
	auditLogDir       = "/var/log/sentinel"
	auditLogFile      = "/var/log/sentinel/audit.jsonl"
	auditMaxSizeBytes = 10 * 1024 * 1024 // 10MB
)

type SentinelAuditEvent struct {
	SchemaVersion string                 `json:"schema_version"`
	Timestamp     string                 `json:"timestamp"`
	Component     string                 `json:"component"`
	EventType     string                 `json:"event_type"`
	Severity      string                 `json:"severity"`
	Action        string                 `json:"action"`
	Metadata      map[string]interface{} `json:"metadata"`
}

func (d *TelosDaemon) initDurableAuditLogger() error {
	if err := os.MkdirAll(auditLogDir, 0750); err != nil {
		return fmt.Errorf("create audit log dir: %w", err)
	}

	f, err := os.OpenFile(auditLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	d.alertFile = f
	return nil
}

func (d *TelosDaemon) EmitAudit(event SentinelAuditEvent) {
	if d.alertFile == nil {
		return
	}

	event.SchemaVersion = "1.0"
	event.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)

	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	data = append(data, '\n')

	d.alertMu.Lock()
	defer d.alertMu.Unlock()

	// Check file size for rotation
	if stat, err := d.alertFile.Stat(); err == nil {
		if stat.Size() > auditMaxSizeBytes {
			d.alertFile.Close()
			os.Rename(auditLogFile, auditLogFile+".1")
			f, err := os.OpenFile(auditLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
			if err != nil {
				log.Printf("[AuditLog] Failed to rotate: %v", err)
				d.alertFile = nil
				return
			}
			d.alertFile = f
			log.Println("✓ Audit log rotated → audit.jsonl.1")
		}
	}

	d.alertFile.Write(data)
	// TODO: Under heavy volumetric attack, calling fsync on every write will cause
	// significant performance stalls. Future versions should use a buffered writer
	// with a size/time-based flush (e.g., every 500ms or 1MB).
	d.alertFile.Sync()
}
