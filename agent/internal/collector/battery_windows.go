//go:build windows

package collector

import (
	"context"
	"encoding/json"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// adjustBatteryForOS fills in lifetime cycle count on Windows. The distatus
// library doesn't expose it, and Windows has no single canonical source —
// we try two paths in order:
//
//  1. WMI BatteryCycleCount (root\WMI namespace) via PowerShell. Fast,
//     no syscalls, works on most modern laptops where the firmware exposes
//     _BIX cycle count and the WMI class is registered.
//  2. DeviceIoControl with IOCTL_BATTERY_QUERY_INFORMATION. Same data
//     source `powercfg /batteryreport` uses internally. Catches laptops
//     where the WMI class isn't registered but the kernel battery API
//     still works.
//
// If both fail (very old firmware that doesn't track cycles, or a
// hypervisor's synthetic battery) we leave CycleCount at 0 and the UI
// shows "—" — better than guessing.
func adjustBatteryForOS(ctx context.Context, r *BatteryReading) {
	if r == nil {
		return
	}
	if c := readWindowsCycleCountWMI(ctx); c > 0 {
		r.CycleCount = c
		return
	}
	if c := readWindowsCycleCountIOCTL(); c > 0 {
		r.CycleCount = c
	}
}

// ---------- Method 1: WMI BatteryCycleCount ----------

// readWindowsCycleCountWMI returns the largest CycleCount across all WMI
// BatteryCycleCount rows. 0 on any failure — caller falls through to IOCTL.
func readWindowsCycleCountWMI(ctx context.Context) int {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	const ps = `Get-CimInstance -Namespace root\WMI -ClassName BatteryCycleCount -ErrorAction SilentlyContinue | ` +
		`Select-Object CycleCount | ConvertTo-Json -Compress`
	out, err := exec.CommandContext(cctx,
		"powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps).Output()
	if err != nil || len(out) == 0 {
		return 0
	}

	type cc struct{ CycleCount int }
	var rows []cc
	if jerr := json.Unmarshal(out, &rows); jerr != nil {
		// Single-row case: PowerShell ConvertTo-Json emits an object, not an array.
		var single cc
		if jerr2 := json.Unmarshal(out, &single); jerr2 != nil {
			return 0
		}
		rows = []cc{single}
	}
	var max int
	for _, r := range rows {
		if r.CycleCount > max {
			max = r.CycleCount
		}
	}
	return max
}

// ---------- Method 2: DeviceIoControl on battery class devices ----------

var (
	setupapi                             = windows.NewLazySystemDLL("setupapi.dll")
	procSetupDiGetClassDevsW             = setupapi.NewProc("SetupDiGetClassDevsW")
	procSetupDiEnumDeviceInterfaces      = setupapi.NewProc("SetupDiEnumDeviceInterfaces")
	procSetupDiGetDeviceInterfaceDetailW = setupapi.NewProc("SetupDiGetDeviceInterfaceDetailW")
	procSetupDiDestroyDeviceInfoList     = setupapi.NewProc("SetupDiDestroyDeviceInfoList")
)

// GUID_DEVICE_BATTERY (battery class driver interface).
// {72631e54-78a4-11d0-bcf7-00aa00b7b32a}
var guidDeviceBattery = windows.GUID{
	Data1: 0x72631e54,
	Data2: 0x78a4,
	Data3: 0x11d0,
	Data4: [8]byte{0xbc, 0xf7, 0x00, 0xaa, 0x00, 0xb7, 0xb3, 0x2a},
}

const (
	digcfPresent         = 0x02
	digcfDeviceInterface = 0x10

	// CTL_CODE(FILE_DEVICE_BATTERY=0x29, fn, METHOD_BUFFERED=0, FILE_READ_ACCESS=1)
	ioctlBatteryQueryTag         = 0x00294040 // fn 0x10
	ioctlBatteryQueryInformation = 0x00294044 // fn 0x11

	// BATTERY_QUERY_INFORMATION_LEVEL.BatteryInformation
	batteryInformationLevel = 0
)

type spDeviceInterfaceData struct {
	cbSize             uint32
	InterfaceClassGuid windows.GUID
	Flags              uint32
	Reserved           uintptr
}

// BATTERY_QUERY_INFORMATION (winioctl.h).
type batteryQueryInformation struct {
	BatteryTag       uint32
	InformationLevel uint32
	AtRate           int32
}

// BATTERY_INFORMATION (winioctl.h). 36 bytes, naturally aligned. The 3-byte
// Reserved field after Technology is required so the C and Go struct layouts
// match — without it Chemistry shifts and DesignedCapacity is misaligned.
type batteryInformation struct {
	Capabilities        uint32
	Technology          byte
	Reserved            [3]byte
	Chemistry           [4]byte
	DesignedCapacity    uint32
	FullChargedCapacity uint32
	DefaultAlert1       uint32
	DefaultAlert2       uint32
	CriticalBias        uint32
	CycleCount          uint32
}

// readWindowsCycleCountIOCTL enumerates battery interface devices via SetupAPI,
// opens each, and asks for its BatteryInformation. Returns the largest
// CycleCount across all batteries (multi-battery laptops are rare but exist).
func readWindowsCycleCountIOCTL() int {
	hDevInfo, _, _ := procSetupDiGetClassDevsW.Call(
		uintptr(unsafe.Pointer(&guidDeviceBattery)),
		0,
		0,
		uintptr(digcfPresent|digcfDeviceInterface),
	)
	// SetupDiGetClassDevs returns INVALID_HANDLE_VALUE (= -1 cast) on failure.
	if hDevInfo == 0 || hDevInfo == uintptr(syscall.InvalidHandle) {
		return 0
	}
	defer procSetupDiDestroyDeviceInfoList.Call(hDevInfo)

	var maxCycles int
	for i := uint32(0); i < 16; i++ {
		var did spDeviceInterfaceData
		did.cbSize = uint32(unsafe.Sizeof(did))

		r, _, _ := procSetupDiEnumDeviceInterfaces.Call(
			hDevInfo,
			0,
			uintptr(unsafe.Pointer(&guidDeviceBattery)),
			uintptr(i),
			uintptr(unsafe.Pointer(&did)),
		)
		if r == 0 {
			break // no more devices
		}

		// First call: probe for required buffer size.
		var requiredSize uint32
		procSetupDiGetDeviceInterfaceDetailW.Call(
			hDevInfo,
			uintptr(unsafe.Pointer(&did)),
			0, 0,
			uintptr(unsafe.Pointer(&requiredSize)),
			0,
		)
		if requiredSize < 6 {
			continue
		}

		buf := make([]byte, requiredSize)
		// The struct's cbSize is sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W)
		// which is 8 on x64 (4-byte DWORD + 2-byte WCHAR[1] + 2 padding)
		// and 6 on x86 (4 + 2). Anything else returns ERROR_INVALID_USER_BUFFER.
		// This is a documented Windows quirk.
		cbSize := uint32(8)
		if unsafe.Sizeof(uintptr(0)) == 4 {
			cbSize = 6
		}
		*(*uint32)(unsafe.Pointer(&buf[0])) = cbSize

		r, _, _ = procSetupDiGetDeviceInterfaceDetailW.Call(
			hDevInfo,
			uintptr(unsafe.Pointer(&did)),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(requiredSize),
			0, 0,
		)
		if r == 0 {
			continue
		}

		// The DevicePath field is a wide string starting right after cbSize
		// (offset 4 from the beginning of the struct).
		pathPtr := (*uint16)(unsafe.Pointer(&buf[4]))
		path := windows.UTF16PtrToString(pathPtr)
		if path == "" {
			continue
		}

		if c := queryBatteryCycleCount(path); c > maxCycles {
			maxCycles = c
		}
	}
	return maxCycles
}

// queryBatteryCycleCount opens a battery device by path, retrieves its tag,
// then queries BatteryInformation. Returns the CycleCount on success, 0
// otherwise.
func queryBatteryCycleCount(devicePath string) int {
	pathPtr, err := windows.UTF16PtrFromString(devicePath)
	if err != nil {
		return 0
	}
	// dwDesiredAccess=0 is the documented pattern for read-only battery IOCTLs.
	handle, err := windows.CreateFile(
		pathPtr,
		0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(handle)

	// 1) Fetch the battery tag — required as input for every subsequent
	// QueryInformation call. Wait-time 0 = don't block.
	var tagWaitMs uint32 = 0
	var tag uint32
	var bytesReturned uint32
	if err := windows.DeviceIoControl(
		handle,
		ioctlBatteryQueryTag,
		(*byte)(unsafe.Pointer(&tagWaitMs)), uint32(unsafe.Sizeof(tagWaitMs)),
		(*byte)(unsafe.Pointer(&tag)), uint32(unsafe.Sizeof(tag)),
		&bytesReturned, nil,
	); err != nil || tag == 0 {
		return 0
	}

	// 2) Query BatteryInformation for that tag.
	bqi := batteryQueryInformation{
		BatteryTag:       tag,
		InformationLevel: batteryInformationLevel,
	}
	var info batteryInformation
	if err := windows.DeviceIoControl(
		handle,
		ioctlBatteryQueryInformation,
		(*byte)(unsafe.Pointer(&bqi)), uint32(unsafe.Sizeof(bqi)),
		(*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)),
		&bytesReturned, nil,
	); err != nil {
		return 0
	}
	return int(info.CycleCount)
}
