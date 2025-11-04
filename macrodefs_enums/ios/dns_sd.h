// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/dns_sd.h

enum macro_dns_sd_h {
/*line: 69*/    _DNS_SD_H = 0x9afaaecc,  // 2600120012
};

enum macro_dns_sd_version {
/* DNS-SD API version strings are of the form x[.y[.z]].
 * Version strings less than or equal to 1661 are encoded as (x * 10000) + (y * 100) + z, where 0 ≤ y,z ≤ 99.
 * Version strings greater than 1661 are encoded as (x * 1000000) + (y * 1000) + z, where 0 ≤ y,z ≤ 999.
 * Therefore, the greatest version number for the original encoding is 16610000.
 */
/*line: 76*/    DNS_SD_ORIGINAL_ENCODING_VERSION_NUMBER_MAX = 0xfd72d0,  // 16610000
};

enum macro_dns_sd_libdispatch {
/*line: 92*/    _DNS_SD_LIBDISPATCH = 0x1,  // 1
};

enum macro_dns_service_limits {
/* literal C-String, including the terminating NULL at the end. */
/*line: 799*/   kDNSServiceMaxServiceName = 0x40,  // 64
/* including the final trailing dot, and the C-String terminating NULL at the end. */
/*line: 804*/   kDNSServiceMaxDomainName = 0x3f1,  // 1009
};

// Depends on identifiers
enum macro_interface_indices {
/*
 * Constants for specifying an interface index
 *
 * Specific interface indexes are identified via a 32-bit unsigned integer returned
 * by the if_nametoindex() family of calls.
 *
 * If the client passes 0 for interface index, that means "do the right thing",
 * which (at present) means, "if the name is in an mDNS local multicast domain
 * (e.g. 'local.', '254.169.in-addr.arpa.', '{8,9,A,B}.E.F.ip6.arpa.') then multicast
 * on all applicable interfaces, otherwise send via unicast to the appropriate
 * DNS server." Normally, most clients will use 0 for interface index to
 * automatically get the default sensible behaviour.
 *
 * If the client passes a positive interface index, then that indicates to do the
 * operation only on that one specified interface.
 *
 * If the client passes kDNSServiceInterfaceIndexLocalOnly when registering
 * a service, then that service will be found *only* by other local clients
 * on the same machine that are browsing using kDNSServiceInterfaceIndexLocalOnly
 * or kDNSServiceInterfaceIndexAny.
 * If a client has a 'private' service, accessible only to other processes
 * running on the same machine, this allows the client to advertise that service
 * in a way such that it does not inadvertently appear in service lists on
 * all the other machines on the network.
 *
 * If the client passes kDNSServiceInterfaceIndexLocalOnly when querying or
 * browsing, then the LocalOnly authoritative records and /etc/hosts caches
 * are searched and will find *all* records registered or configured on that
 * same local machine.
 *
 * If interested in getting negative answers to local questions while querying
 * or browsing, then set both the kDNSServiceInterfaceIndexLocalOnly and the
 * kDNSServiceFlagsReturnIntermediates flags. If no local answers exist at this
 * moment in time, then the reply will return an immediate negative answer. If
 * local records are subsequently created that answer the question, then those
 * answers will be delivered, for as long as the question is still active.
 *
 * If the kDNSServiceFlagsTimeout and kDNSServiceInterfaceIndexLocalOnly flags
 * are set simultaneously when either DNSServiceQueryRecord or DNSServiceGetAddrInfo
 * is called then both flags take effect. However, if DNSServiceQueryRecord is called
 * with both the kDNSServiceFlagsSuppressUnusable and kDNSServiceInterfaceIndexLocalOnly
 * flags set, then the kDNSServiceFlagsSuppressUnusable flag is ignored.
 *
 * Clients explicitly wishing to discover *only* LocalOnly services during a
 * browse may do this, without flags, by inspecting the interfaceIndex of each
 * service reported to a DNSServiceBrowseReply() callback function, and
 * discarding those answers where the interface index is not set to
 * kDNSServiceInterfaceIndexLocalOnly.
 *
 * kDNSServiceInterfaceIndexP2P is meaningful only in Browse, QueryRecord, Register,
 * and Resolve operations. It should not be used in other DNSService APIs.
 *
 * - If kDNSServiceInterfaceIndexP2P is passed to DNSServiceBrowse or
 *   DNSServiceQueryRecord, it restricts the operation to P2P.
 *
 * - If kDNSServiceInterfaceIndexP2P is passed to DNSServiceRegister, it is
 *   mapped internally to kDNSServiceInterfaceIndexAny with the kDNSServiceFlagsIncludeP2P
 *   set.
 *
 * - If kDNSServiceInterfaceIndexP2P is passed to DNSServiceResolve, it is
 *   mapped internally to kDNSServiceInterfaceIndexAny with the kDNSServiceFlagsIncludeP2P
 *   set, because resolving a P2P service may create and/or enable an interface whose
 *   index is not known a priori. The resolve callback will indicate the index of the
 *   interface via which the service can be accessed.
 *
 * If applications pass kDNSServiceInterfaceIndexAny to DNSServiceBrowse
 * or DNSServiceQueryRecord, they must set the kDNSServiceFlagsIncludeP2P flag
 * to include P2P. In this case, if a service instance or the record being queried
 * is found over P2P, the resulting ADD event will indicate kDNSServiceInterfaceIndexP2P
 * as the interface index.
 */
/*line: 969*/   kDNSServiceInterfaceIndexAny = 0x0,  // 0
/*line: 970*/   kDNSServiceInterfaceIndexLocalOnly = 0xffffffff,  // ((uint32_t)0xffffffffU)
/*line: 971*/   kDNSServiceInterfaceIndexUnicast = 0xfffffffe,  // ((uint32_t)0xfffffffeU)
/*line: 972*/   kDNSServiceInterfaceIndexP2P = 0xfffffffd,  // ((uint32_t)0xfffffffdU)
/*line: 973*/   kDNSServiceInterfaceIndexBLE = 0xfffffffc,  // ((uint32_t)0xfffffffcU)
/*line: 974*/   kDNSServiceInterfaceIndexInfra = 0xfffffffb, // Reserved, not used by DNSService API // ((uint32_t)0xfffffffbU)
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 165
// #define DNS_SERVICE_FLAGS_ENUM enum2:tuint32_t

// Line: 176
// #define DNS_SD_NULLABLE _Nullable

// Line: 177
// #define DNS_SD_NONNULL _Nonnull

