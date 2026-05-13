// Package wsproto defines the WebSocket message envelopes the agent exchanges
// with the backend. Mirrors backend/BE/src/agents/ws/protocol.ts byte-for-byte.
//
// Each WebSocket text frame holds exactly one JSON object with a `type` field.
// Add new message types in BOTH files together.
package wsproto

import "github.com/itom-mini/agent/internal/collector"

// ----- Client → Server -----

const (
	TypeHello             = "hello"
	TypeMetrics           = "metrics"
	TypeProcesses         = "processes"
	TypeBattery           = "battery"
	TypeSensors           = "sensors"
	TypeGPU               = "gpu"
	TypeSoftwareInventory = "software_inventory"
	TypeBye               = "bye"
)

type Hello struct {
	Type            string `json:"type"`
	AgentID         string `json:"agentId"`
	AgentVersion    string `json:"agentVersion"`
	FingerprintHash string `json:"fingerprintHash,omitempty"`
}

type Metrics struct {
	Type      string             `json:"type"`
	RequestID string             `json:"requestId"`
	Samples   []collector.Sample `json:"samples"`
}

type Bye struct {
	Type string `json:"type"`
}

type Processes struct {
	Type      string                    `json:"type"`
	RequestID string                    `json:"requestId"`
	Timestamp string                    `json:"timestamp"`
	Processes []collector.ProcessSample `json:"processes"`
}

// Battery wraps a BatteryReading with envelope fields.
type Battery struct {
	Type      string `json:"type"`
	RequestID string `json:"requestId"`
	Timestamp string `json:"timestamp"`
	collector.BatteryReading
}

type Sensors struct {
	Type      string                    `json:"type"`
	RequestID string                    `json:"requestId"`
	Timestamp string                    `json:"timestamp"`
	Readings  []collector.SensorReading `json:"readings"`
}

type GPU struct {
	Type      string                `json:"type"`
	RequestID string                `json:"requestId"`
	Timestamp string                `json:"timestamp"`
	GPUs      []collector.GPUSample `json:"gpus"`
}

type SoftwareInventory struct {
	Type      string                   `json:"type"`
	RequestID string                   `json:"requestId"`
	Timestamp string                   `json:"timestamp"`
	Items     []collector.SoftwareItem `json:"items"`
}

// ----- Server → Client -----

const (
	TypeWelcome      = "welcome"
	TypeAck          = "ack"
	TypeError        = "error"
	TypeConfigUpdate = "config_update"
)

type Welcome struct {
	Type                     string `json:"type"`
	AgentID                  string `json:"agentId"`
	Reassigned               bool   `json:"reassigned"`
	HeartbeatIntervalSeconds int    `json:"heartbeatIntervalSeconds"`
}

const (
	AckCommitted = "committed"
	AckDuplicate = "duplicate"
	AckRejected  = "rejected"
)

type Ack struct {
	Type      string `json:"type"`
	RequestID string `json:"requestId"`
	Result    string `json:"result"`
	Message   string `json:"message,omitempty"`
}

type Error struct {
	Type    string `json:"type"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type ConfigUpdate struct {
	Type            string `json:"type"`
	IntervalSeconds int    `json:"intervalSeconds,omitempty"`
}

// Envelope is used to peek at `type` before unmarshalling the full message.
type Envelope struct {
	Type string `json:"type"`
}
