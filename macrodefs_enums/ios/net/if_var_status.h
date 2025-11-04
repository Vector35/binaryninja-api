// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/net/if_var_status.h

// Depends on identifiers
enum macro_if_status_flags {
/*
 * Interface link status report -- includes statistics related to
 * the link layer technology sent by the driver. The driver will monitor
 * these statistics over an interval (3-4 secs) and will generate a report
 * to the network stack. This will give first-hand information about the
 * status of the first hop of the network path. The version and
 * length values should be correct for the data to be processed correctly.
 * The definitions are different for different kind of interfaces like
 * Wifi, Cellular etc,.
 */
/*line: 82*/    IF_CELLULAR_STATUS_REPORT_VERSION_1 = 0x1,  // 1
/*line: 83*/    IF_WIFI_STATUS_REPORT_VERSION_1 = 0x1,  // 1
/*line: 84*/    IF_CELLULAR_STATUS_REPORT_CURRENT_VERSION = 0x1,  // IF_CELLULAR_STATUS_REPORT_VERSION_1
/*line: 86*/    IF_WIFI_STATUS_REPORT_CURRENT_VERSION = 0x1,  // IF_WIFI_STATUS_REPORT_VERSION_1
/*line: 96*/    IF_CELL_LINK_QUALITY_METRIC_VALID = 0x1,  // 0x1
/*line: 97*/    IF_CELL_UL_EFFECTIVE_BANDWIDTH_VALID = 0x2,  // 0x2
/*line: 98*/    IF_CELL_UL_MAX_BANDWIDTH_VALID = 0x4,  // 0x4
/*line: 99*/    IF_CELL_UL_MIN_LATENCY_VALID = 0x8,  // 0x8
/*line: 100*/   IF_CELL_UL_EFFECTIVE_LATENCY_VALID = 0x10,  // 0x10
/*line: 101*/   IF_CELL_UL_MAX_LATENCY_VALID = 0x20,  // 0x20
/*line: 102*/   IF_CELL_UL_RETXT_LEVEL_VALID = 0x40,  // 0x40
/*line: 103*/   IF_CELL_UL_BYTES_LOST_VALID = 0x80,  // 0x80
/*line: 104*/   IF_CELL_UL_MIN_QUEUE_SIZE_VALID = 0x100,  // 0x100
/*line: 105*/   IF_CELL_UL_AVG_QUEUE_SIZE_VALID = 0x200,  // 0x200
/*line: 106*/   IF_CELL_UL_MAX_QUEUE_SIZE_VALID = 0x400,  // 0x400
/*line: 107*/   IF_CELL_DL_EFFECTIVE_BANDWIDTH_VALID = 0x800,  // 0x800
/*line: 108*/   IF_CELL_DL_MAX_BANDWIDTH_VALID = 0x1000,  // 0x1000
/*line: 109*/   IF_CELL_CONFIG_INACTIVITY_TIME_VALID = 0x2000,  // 0x2000
/*line: 110*/   IF_CELL_CONFIG_BACKOFF_TIME_VALID = 0x4000,  // 0x4000
/*line: 111*/   IF_CELL_UL_MSS_RECOMMENDED_VALID = 0x8000,  // 0x8000
};

enum macro_cell_ul_status {
/*line: 120*/   IF_CELL_UL_RETXT_LEVEL_NONE = 0x1,  // 1
/*line: 121*/   IF_CELL_UL_RETXT_LEVEL_LOW = 0x2,  // 2
/*line: 122*/   IF_CELL_UL_RETXT_LEVEL_MEDIUM = 0x3,  // 3
/*line: 123*/   IF_CELL_UL_RETXT_LEVEL_HIGH = 0x4,  // 4
/*line: 132*/   IF_CELL_UL_MSS_RECOMMENDED_NONE = 0x0, /* Use default */ // 0x0
/*line: 133*/   IF_CELL_UL_MSS_RECOMMENDED_MEDIUM = 0x1, /* 1200 byte MSS */ // 0x1
/*line: 134*/   IF_CELL_UL_MSS_RECOMMENDED_LOW = 0x2, /* 512 byte MSS */ // 0x2
};

enum macro_wifi_status_flags {
/*line: 159*/   IF_WIFI_LINK_QUALITY_METRIC_VALID = 0x1,  // 0x1
/*line: 160*/   IF_WIFI_UL_EFFECTIVE_BANDWIDTH_VALID = 0x2,  // 0x2
/*line: 161*/   IF_WIFI_UL_MAX_BANDWIDTH_VALID = 0x4,  // 0x4
/*line: 162*/   IF_WIFI_UL_MIN_LATENCY_VALID = 0x8,  // 0x8
/*line: 163*/   IF_WIFI_UL_EFFECTIVE_LATENCY_VALID = 0x10,  // 0x10
/*line: 164*/   IF_WIFI_UL_MAX_LATENCY_VALID = 0x20,  // 0x20
/*line: 165*/   IF_WIFI_UL_RETXT_LEVEL_VALID = 0x40,  // 0x40
/*line: 166*/   IF_WIFI_UL_ERROR_RATE_VALID = 0x80,  // 0x80
/*line: 167*/   IF_WIFI_UL_BYTES_LOST_VALID = 0x100,  // 0x100
/*line: 168*/   IF_WIFI_DL_EFFECTIVE_BANDWIDTH_VALID = 0x200,  // 0x200
/*line: 169*/   IF_WIFI_DL_MAX_BANDWIDTH_VALID = 0x400,  // 0x400
/*line: 170*/   IF_WIFI_DL_MIN_LATENCY_VALID = 0x800,  // 0x800
/*line: 171*/   IF_WIFI_DL_EFFECTIVE_LATENCY_VALID = 0x1000,  // 0x1000
/*line: 172*/   IF_WIFI_DL_MAX_LATENCY_VALID = 0x2000,  // 0x2000
/*line: 173*/   IF_WIFI_DL_ERROR_RATE_VALID = 0x4000,  // 0x4000
/*line: 174*/   IF_WIFI_CONFIG_FREQUENCY_VALID = 0x8000,  // 0x8000
/*line: 175*/   IF_WIFI_CONFIG_MULTICAST_RATE_VALID = 0x10000,  // 0x10000
/*line: 176*/   IF_WIFI_CONFIG_SCAN_COUNT_VALID = 0x20000,  // 0x20000
/*line: 177*/   IF_WIFI_CONFIG_SCAN_DURATION_VALID = 0x40000,  // 0x40000
/*line: 185*/   IF_WIFI_UL_RETXT_LEVEL_NONE = 0x1,  // 1
/*line: 186*/   IF_WIFI_UL_RETXT_LEVEL_LOW = 0x2,  // 2
/*line: 187*/   IF_WIFI_UL_RETXT_LEVEL_MEDIUM = 0x3,  // 3
/*line: 188*/   IF_WIFI_UL_RETXT_LEVEL_HIGH = 0x4,  // 4
/*line: 204*/   IF_WIFI_CONFIG_FREQUENCY_2_4_GHZ = 0x1,  // 1
/*line: 205*/   IF_WIFI_CONFIG_FREQUENCY_5_0_GHZ = 0x2,  // 2
};

enum macro_radio_contenders {
/*
	 * bitmap of all radio contenders.
	 */
/*line: 406*/   IF_INTERFACE_ADVISORY_WIFI_RADIO_COEX_BT = 0x1,  // 0x01
/*line: 407*/   IF_INTERFACE_ADVISORY_WIFI_RADIO_COEX_AWDL = 0x2,  // 0x02
/*
	 * bitrate information for each queue (in Kbps).
	 */
/*line: 416*/   IF_INTERFACE_ADVISORY_WIFI_TX_QUEUE_COUNT = 0x6,  // 6
};

enum macro_cellular_outage_state {
/*
	 * Cellular outage state: i.e. handover in progress.
	 *     0 - no outage
	 *     1 - outage.
	 */
/*line: 470*/   IF_INTERFACE_ADVISORY_CELL_OUTAGE_STATE_NO = 0x0,  // 0
/*line: 471*/   IF_INTERFACE_ADVISORY_CELL_OUTAGE_STATE_YES = 0x1,  // 1
/* Reserving 1 for link layer */
/*line: 593*/   IFNET_TRAFFIC_DESCRIPTOR_TYPE_INET = 0x2,  // 2
};

enum macro_traffic_direction {
/* Supported flags */
/*line: 596*/   IFNET_TRAFFIC_DESCRIPTOR_FLAG_INBOUND = 0x1,  // 0x0001
/*line: 597*/   IFNET_TRAFFIC_DESCRIPTOR_FLAG_OUTBOUND = 0x2,  // 0x0002
};

enum macro_inet_traffic_descriptors {
/*line: 606*/   IFNET_TRAFFIC_DESCRIPTOR_INET_IPVER = 0x1,  // 0x01
/*line: 607*/   IFNET_TRAFFIC_DESCRIPTOR_INET_PROTO = 0x2,  // 0x02
/*line: 608*/   IFNET_TRAFFIC_DESCRIPTOR_INET_LADDR = 0x4,  // 0x04
/*line: 609*/   IFNET_TRAFFIC_DESCRIPTOR_INET_RADDR = 0x8,  // 0x08
/*line: 610*/   IFNET_TRAFFIC_DESCRIPTOR_INET_LPORT = 0x10,  // 0x10
/*line: 611*/   IFNET_TRAFFIC_DESCRIPTOR_INET_RPORT = 0x20,  // 0x20
};

enum macro_traffic_rule_action {
/*line: 634*/   IFNET_TRAFFIC_RULE_ACTION_STEER = 0x1,  // 1
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 620
// #define iia_v4addr addr32[3]

