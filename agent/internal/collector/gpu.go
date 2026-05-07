package collector

import (
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// CollectGPU shells out to `nvidia-smi` and parses CSV output. NVIDIA only.
// On hosts without nvidia-smi (most laptops, AMD/Intel-only machines, all
// macOS) we return ErrNoGPU and the caller skips emitting a frame.
//
// We pin specific query columns and parse them positionally — much safer
// than parsing the human-readable nvidia-smi output.
var ErrNoGPU = errors.New("no nvidia gpu detected")

const nvidiaSMIQuery = "index,name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw"

func CollectGPU(ctx context.Context) ([]GPUSample, error) {
	if _, err := exec.LookPath("nvidia-smi"); err != nil {
		return nil, ErrNoGPU
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cctx,
		"nvidia-smi",
		"--query-gpu="+nvidiaSMIQuery,
		"--format=csv,noheader,nounits",
	)
	raw, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var out []GPUSample
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		fields := splitCSV(line)
		if len(fields) < 7 {
			continue
		}
		idx, _ := strconv.Atoi(fields[0])
		util, _ := strconv.ParseFloat(fields[2], 64)
		memUsedMB, _ := strconv.ParseFloat(fields[3], 64)
		memTotalMB, _ := strconv.ParseFloat(fields[4], 64)
		temp, _ := strconv.ParseFloat(fields[5], 64)
		power, _ := strconv.ParseFloat(fields[6], 64)

		out = append(out, GPUSample{
			Index:              idx,
			Name:               fields[1],
			UtilizationPercent: util,
			MemoryUsedBytes:    uint64(memUsedMB * 1024 * 1024),
			MemoryTotalBytes:   uint64(memTotalMB * 1024 * 1024),
			TemperatureC:       temp,
			PowerWatts:         power,
		})
	}
	if len(out) == 0 {
		return nil, ErrNoGPU
	}
	return out, nil
}

func splitCSV(line string) []string {
	parts := strings.Split(line, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
