// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/sockio.h

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 73
// #define SIOCSHIWAT _IOW('s',  0, int)

// Line: 74
// #define SIOCGHIWAT _IOR('s',  1, int)

// Line: 75
// #define SIOCSLOWAT _IOW('s',  2, int)

// Line: 76
// #define SIOCGLOWAT _IOR('s',  3, int)

// Line: 77
// #define SIOCATMARK _IOR('s',  7, int)

// Line: 78
// #define SIOCSPGRP _IOW('s',  8, int)

// Line: 79
// #define SIOCGPGRP _IOR('s',  9, int)

// Line: 81
// #define SIOCSIFADDR _IOW('i', 12, struct ifreq)

// Line: 82
// #define SIOCSIFDSTADDR _IOW('i', 14, struct ifreq)

// Line: 83
// #define SIOCSIFFLAGS _IOW('i', 16, struct ifreq)

// Line: 84
// #define SIOCGIFFLAGS _IOWR('i', 17, struct ifreq)

// Line: 85
// #define SIOCSIFBRDADDR _IOW('i', 19, struct ifreq)

// Line: 86
// #define SIOCSIFNETMASK _IOW('i', 22, struct ifreq)

// Line: 87
// #define SIOCGIFMETRIC _IOWR('i', 23, struct ifreq)

// Line: 88
// #define SIOCSIFMETRIC _IOW('i', 24, struct ifreq)

// Line: 89
// #define SIOCDIFADDR _IOW('i', 25, struct ifreq)

// Line: 90
// #define SIOCAIFADDR _IOW('i', 26, struct ifaliasreq)

// Line: 92
// #define SIOCGIFADDR _IOWR('i', 33, struct ifreq)

// Line: 93
// #define SIOCGIFDSTADDR _IOWR('i', 34, struct ifreq)

// Line: 94
// #define SIOCGIFBRDADDR _IOWR('i', 35, struct ifreq)

// Line: 95
// #define SIOCGIFCONF _IOWR('i', 36, struct ifconf)

// Line: 96
// #define SIOCGIFNETMASK _IOWR('i', 37, struct ifreq)

// Line: 97
// #define SIOCAUTOADDR _IOWR('i', 38, struct ifreq)

// Line: 98
// #define SIOCAUTONETMASK _IOW('i', 39, struct ifreq)

// Line: 99
// #define SIOCARPIPLL _IOWR('i', 40, struct ifreq)

// Line: 101
// #define SIOCADDMULTI _IOW('i', 49, struct ifreq)

// Line: 102
// #define SIOCDELMULTI _IOW('i', 50, struct ifreq)

// Line: 103
// #define SIOCGIFMTU _IOWR('i', 51, struct ifreq)

// Line: 104
// #define SIOCSIFMTU _IOW('i', 52, struct ifreq)

// Line: 105
// #define SIOCGIFPHYS _IOWR('i', 53, struct ifreq)

// Line: 106
// #define SIOCSIFPHYS _IOW('i', 54, struct ifreq)

// Line: 107
// #define SIOCSIFMEDIA _IOWR('i', 55, struct ifreq)

// Line: 113
// #define SIOCGIFMEDIA _IOWR('i', 56, struct ifmediareq)

// Line: 115
// #define SIOCSIFGENERIC _IOW('i', 57, struct ifreq)

// Line: 116
// #define SIOCGIFGENERIC _IOWR('i', 58, struct ifreq)

// Line: 117
// #define SIOCRSLVMULTI _IOWR('i', 59, struct rslvmulti_req)

// Line: 119
// #define SIOCSIFLLADDR _IOW('i', 60, struct ifreq)

// Line: 120
// #define SIOCGIFSTATUS _IOWR('i', 61, struct ifstat)

// Line: 121
// #define SIOCSIFPHYADDR _IOW('i', 62, struct ifaliasreq)

// Line: 122
// #define SIOCGIFPSRCADDR _IOWR('i', 63, struct ifreq)

// Line: 123
// #define SIOCGIFPDSTADDR _IOWR('i', 64, struct ifreq)

// Line: 124
// #define SIOCDIFPHYADDR _IOW('i', 65, struct ifreq)

// Line: 126
// #define SIOCGIFDEVMTU _IOWR('i', 68, struct ifreq)

// Line: 127
// #define SIOCSIFALTMTU _IOW('i', 69, struct ifreq)

// Line: 128
// #define SIOCGIFALTMTU _IOWR('i', 72, struct ifreq)

// Line: 129
// #define SIOCSIFBOND _IOW('i', 70, struct ifreq)

// Line: 130
// #define SIOCGIFBOND _IOWR('i', 71, struct ifreq)

// Line: 139
// #define SIOCGIFXMEDIA _IOWR('i', 72, struct ifmediareq)

// Line: 141
// #define SIOCSIFCAP _IOW('i', 90, struct ifreq)

// Line: 142
// #define SIOCGIFCAP _IOWR('i', 91, struct ifreq)

// Line: 144
// #define SIOCSIFMANAGEMENT _IOWR('i', 92, struct ifreq)

// Line: 146
// #define SIOCIFCREATE _IOWR('i', 120, struct ifreq)

// Line: 147
// #define SIOCIFDESTROY _IOW('i', 121, struct ifreq)

// Line: 148
// #define SIOCIFCREATE2 _IOWR('i', 122, struct ifreq)

// Line: 150
// #define SIOCSDRVSPEC _IOW('i', 123, struct ifdrv)

// Line: 152
// #define SIOCGDRVSPEC _IOWR('i', 123, struct ifdrv)

// Line: 154
// #define SIOCSIFVLAN _IOW('i', 126, struct ifreq)

// Line: 155
// #define SIOCGIFVLAN _IOWR('i', 127, struct ifreq)

// Line: 156
// #define SIOCSETVLAN SIOCSIFVLAN

// Line: 157
// #define SIOCGETVLAN SIOCGIFVLAN

// Line: 159
// #define SIOCIFGCLONERS _IOWR('i', 129, struct if_clonereq)

// Line: 161
// #define SIOCGIFASYNCMAP _IOWR('i', 124, struct ifreq)

// Line: 162
// #define SIOCSIFASYNCMAP _IOW('i', 125, struct ifreq)

// Line: 165
// #define SIOCGIFMAC _IOWR('i', 130, struct ifreq)

// Line: 166
// #define SIOCSIFMAC _IOW('i', 131, struct ifreq)

// Line: 167
// #define SIOCSIFKPI _IOW('i', 134, struct ifreq)

// Line: 168
// #define SIOCGIFKPI _IOWR('i', 135, struct ifreq)

// Line: 170
// #define SIOCGIFWAKEFLAGS _IOWR('i', 136, struct ifreq)

// Line: 172
// #define SIOCGIFFUNCTIONALTYPE _IOWR('i', 173, struct ifreq)

// Line: 174
// #define SIOCSIF6LOWPAN _IOW('i', 196, struct ifreq)

// Line: 175
// #define SIOCGIF6LOWPAN _IOWR('i', 197, struct ifreq)

// Line: 177
// #define SIOCGIFDIRECTLINK _IOWR('i', 222, struct ifreq)

