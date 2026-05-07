package collector

// Pure-data payload types used by the new observability collectors. They
// MUST NOT import wsproto — wsproto wraps these in WS envelopes (adding
// Type/RequestID/Timestamp). Keeping the data shapes here lets each
// collector return a typed value without taking on a transport dep.

type ProcessSample struct {
	Name         string  `json:"name"`
	PIDCount     int     `json:"pidCount"`
	CPUPercent   float64 `json:"cpuPercent"`
	MemoryBytes  uint64  `json:"memoryBytes"`
	IOReadBytes  uint64  `json:"ioReadBytes,omitempty"`
	IOWriteBytes uint64  `json:"ioWriteBytes,omitempty"`
}

type BatteryReading struct {
	Percent            float64 `json:"percent"`
	Charging           bool    `json:"charging"`
	OnAC               bool    `json:"onAC"`
	CycleCount         int     `json:"cycleCount,omitempty"`
	DesignCapacityMwh  int     `json:"designCapacityMwh,omitempty"`
	FullCapacityMwh    int     `json:"fullCapacityMwh,omitempty"`
	HealthPercent      float64 `json:"healthPercent,omitempty"`
	TimeToFullSeconds  int     `json:"timeToFullSeconds,omitempty"`
	TimeToEmptySeconds int     `json:"timeToEmptySeconds,omitempty"`
}

type SensorReading struct {
	Name  string  `json:"name"`
	Kind  string  `json:"kind"` // "temperature_c" | "fan_rpm"
	Value float64 `json:"value"`
}

type DriveHealth struct {
	Device              string  `json:"device"`
	Model               string  `json:"model,omitempty"`
	Status              string  `json:"status"`
	PredictedFailure    bool    `json:"predictedFailure"`
	TemperatureC        float64 `json:"temperatureC,omitempty"`
	PowerOnHours        int     `json:"powerOnHours,omitempty"`
	ReallocatedSectors  int     `json:"reallocatedSectors,omitempty"`
	WearLevelingPercent float64 `json:"wearLevelingPercent,omitempty"`
}

type GPUSample struct {
	Index              int     `json:"index"`
	Name               string  `json:"name"`
	UtilizationPercent float64 `json:"utilizationPercent"`
	MemoryUsedBytes    uint64  `json:"memoryUsedBytes"`
	MemoryTotalBytes   uint64  `json:"memoryTotalBytes"`
	TemperatureC       float64 `json:"temperatureC,omitempty"`
	PowerWatts         float64 `json:"powerWatts,omitempty"`
}

type SoftwareItem struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Publisher   string `json:"publisher,omitempty"`
	InstalledAt string `json:"installedAt,omitempty"`
	SizeBytes   uint64 `json:"sizeBytes,omitempty"`
	Source      string `json:"source"`
}
