package snmp

// Named OID constants. Kept here in one place so walkers stay readable
// and we never accidentally fork the canonical numbers across files.
//
// Convention: every OID here is the *table root* (no instance suffix)
// — walkers append a row index, scalars get ".0" suffixed by the
// caller.
const (
	// ----- System group (RFC 1213) -----
	OIDSysDescr    = "1.3.6.1.2.1.1.1" // .0
	OIDSysObjectID = "1.3.6.1.2.1.1.2" // .0
	OIDSysUpTime   = "1.3.6.1.2.1.1.3" // .0
	OIDSysName     = "1.3.6.1.2.1.1.5" // .0
	OIDSysLocation = "1.3.6.1.2.1.1.6" // .0

	// ----- IF-MIB::ifTable + ifXTable -----
	OIDIfDescr        = "1.3.6.1.2.1.2.2.1.2"
	OIDIfType         = "1.3.6.1.2.1.2.2.1.3"
	OIDIfMtu          = "1.3.6.1.2.1.2.2.1.4"
	OIDIfSpeed        = "1.3.6.1.2.1.2.2.1.5"     // 32-bit, wraps at 4G
	OIDIfPhysAddress  = "1.3.6.1.2.1.2.2.1.6"
	OIDIfAdminStatus  = "1.3.6.1.2.1.2.2.1.7"
	OIDIfOperStatus   = "1.3.6.1.2.1.2.2.1.8"
	OIDIfName         = "1.3.6.1.2.1.31.1.1.1.1"  // ifXTable
	OIDIfHighSpeed    = "1.3.6.1.2.1.31.1.1.1.15" // 64-bit, in Mbps
	OIDIfAlias        = "1.3.6.1.2.1.31.1.1.1.18"

	// ----- IP-MIB::ipAddressTable (modern; v4+v6) -----
	OIDIpAddressIfIndex = "1.3.6.1.2.1.4.34.1.3"
	OIDIpAddressType    = "1.3.6.1.2.1.4.34.1.4"
	OIDIpAddressPrefix  = "1.3.6.1.2.1.4.34.1.5"

	// ----- IP-MIB::ipNetToPhysicalTable (modern ARP) -----
	OIDIpNetToPhysicalPhysAddress = "1.3.6.1.2.1.4.35.1.4"
	OIDIpNetToPhysicalType        = "1.3.6.1.2.1.4.35.1.7" // 1=other,2=invalid,3=dynamic,4=static,5=local

	// ----- IP-MIB::ipNetToMediaTable (legacy ARP, v4 only) -----
	OIDIpNetToMediaPhysAddress = "1.3.6.1.2.1.4.22.1.2"
	OIDIpNetToMediaNetAddress  = "1.3.6.1.2.1.4.22.1.3"

	// ----- BRIDGE-MIB::dot1dTpFdbTable (legacy FDB) -----
	OIDDot1dTpFdbPort   = "1.3.6.1.2.1.17.4.3.1.2"
	OIDDot1dTpFdbStatus = "1.3.6.1.2.1.17.4.3.1.3"

	// ----- Q-BRIDGE-MIB::dot1qTpFdbTable (modern, VLAN-aware FDB) -----
	OIDDot1qTpFdbPort   = "1.3.6.1.2.1.17.7.1.2.2.1.2"
	OIDDot1qTpFdbStatus = "1.3.6.1.2.1.17.7.1.2.2.1.3"

	// dot1dBasePortIfIndex maps the bridge "port number" to ifIndex.
	// Required to join FDB entries (which use port numbers) back to
	// the IF-MIB interface rows.
	OIDDot1dBasePortIfIndex = "1.3.6.1.2.1.17.1.4.1.2"

	// ----- IP-FORWARD-MIB::inetCidrRouteTable (modern routes) -----
	OIDInetCidrRouteIfIndex  = "1.3.6.1.2.1.4.24.7.1.7"
	OIDInetCidrRouteType     = "1.3.6.1.2.1.4.24.7.1.8"
	OIDInetCidrRouteProto    = "1.3.6.1.2.1.4.24.7.1.9"
	OIDInetCidrRouteNextHop  = "1.3.6.1.2.1.4.24.7.1.4" // composite key prefix; see walker

	// ----- IP-FORWARD-MIB::ipCidrRouteTable (legacy, v4 only) -----
	OIDIpCidrRouteIfIndex = "1.3.6.1.2.1.4.24.4.1.5"
	OIDIpCidrRouteType    = "1.3.6.1.2.1.4.24.4.1.6"
	OIDIpCidrRouteProto   = "1.3.6.1.2.1.4.24.4.1.7"
	OIDIpCidrRouteNextHop = "1.3.6.1.2.1.4.24.4.1.4" // not stored; key

	// ----- LLDP-MIB::lldpRemTable -----
	// Index: lldpRemTimeMark.lldpRemLocalPortNum.lldpRemIndex
	OIDLldpRemChassisId    = "1.0.8802.1.1.2.1.4.1.1.5"
	OIDLldpRemPortId       = "1.0.8802.1.1.2.1.4.1.1.7"
	OIDLldpRemPortDesc     = "1.0.8802.1.1.2.1.4.1.1.8"
	OIDLldpRemSysName      = "1.0.8802.1.1.2.1.4.1.1.9"
	OIDLldpRemSysDesc      = "1.0.8802.1.1.2.1.4.1.1.10"
	OIDLldpRemManAddrIfId  = "1.0.8802.1.1.2.1.4.2.1.4" // management addresses table

	// lldpLocChassisId — fallback chassis ID when ENTITY-MIB doesn't have one.
	OIDLldpLocChassisId = "1.0.8802.1.1.2.1.3.2" // .0

	// ----- CISCO-CDP-MIB::cdpCacheTable -----
	OIDCdpCacheAddressType  = "1.3.6.1.4.1.9.9.23.1.2.1.1.3"
	OIDCdpCacheAddress      = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"
	OIDCdpCacheVersion      = "1.3.6.1.4.1.9.9.23.1.2.1.1.5"
	OIDCdpCacheDeviceId     = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
	OIDCdpCacheDevicePort   = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
	OIDCdpCachePlatform     = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"

	// ----- ENTITY-MIB::entPhysicalTable (for chassis serial) -----
	OIDEntPhysicalClass     = "1.3.6.1.2.1.47.1.1.1.1.5"
	OIDEntPhysicalDescr     = "1.3.6.1.2.1.47.1.1.1.1.2"
	OIDEntPhysicalSerialNum = "1.3.6.1.2.1.47.1.1.1.1.11"
	OIDEntPhysicalModelName = "1.3.6.1.2.1.47.1.1.1.1.13"
	// entPhysicalClass values we care about:
	EntClassChassis = 3

	// ----- Cisco VTP — list of active VLANs -----
	// vtpVlanState: row exists for every defined VLAN, value=1 if operational.
	OIDVtpVlanState = "1.3.6.1.4.1.9.9.46.1.3.1.1.2"
)
