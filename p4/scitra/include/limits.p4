// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef _SCITRA_LIMITS_GUARD
#define _SCITRA_LIMITS_GUARD

const bit<16> BUS_WIDTH = 64;
const bit<16> MAX_FRAGMENTS = 24;
const bit<16> MAX_PACKET_SIZE = MAX_FRAGMENTS * BUS_WIDTH;

#endif // _SCITRA_LIMITS_GUARD
