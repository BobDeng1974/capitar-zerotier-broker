//
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/md.h>
#include <nng/nng.h>

#define GET32(ptr, v)                                 \
	v = (((uint32_t)((uint8_t)(ptr)[0])) << 24) + \
	    (((uint32_t)((uint8_t)(ptr)[1])) << 16) + \
	    (((uint32_t)((uint8_t)(ptr)[2])) << 8) +  \
	    (((uint32_t)(uint8_t)(ptr)[3]))

#define PUT64(ptr, u)                                        \
	do {                                                 \
		(ptr)[0] = (uint8_t)(((uint64_t)(u)) >> 56); \
		(ptr)[1] = (uint8_t)(((uint64_t)(u)) >> 48); \
		(ptr)[2] = (uint8_t)(((uint64_t)(u)) >> 40); \
		(ptr)[3] = (uint8_t)(((uint64_t)(u)) >> 32); \
		(ptr)[4] = (uint8_t)(((uint64_t)(u)) >> 24); \
		(ptr)[5] = (uint8_t)(((uint64_t)(u)) >> 16); \
		(ptr)[6] = (uint8_t)(((uint64_t)(u)) >> 8);  \
		(ptr)[7] = (uint8_t)((uint64_t)(u));         \
	} while (0)

// TOTP is HOTP, but with the event counter established as the number
// of timesteps since the epoch.  (E.g. 30 sec intervals).  Timesteps
// always round down.  TOTP has the advantage that no need to track
// counter values exists, the clock provides the necessary state.

// DT takes a 20 byte (160-bit) HMAC result, and extracts a 32-bit
// unsigned value from it.  See RFC 4226 5.3
static uint32_t
DT(unsigned char *hash)
{
	int      offset;
	uint32_t result;

	// This really just uses the last byte to figure out which 4 bytes
	// to extract, and then decodes that as a 31-bit big-endian value.

	offset = hash[19] & 0xF; // gives value 0-15 from last byte
	hash   = &hash[offset];
	GET32(hash, result);
	return (result & 0x7FFFFFFFu);
}

// This generates an OTP authentication.  Only SHA-1 is supported, but
// we don't know of any OTP implementations that use or support other
// hash algorithms.
void
otp(char *buf, size_t bufsz, const unsigned char *key, size_t keylen,
    int digits, uint64_t events)
{
	unsigned char        hash[20];
	unsigned char        evbuf[8];
	mbedtls_md_context_t ctx;
	mbedtls_md_info_t *  info;
	uint32_t             s;
	uint32_t             m;

	// Write the events counter as a 64-bit value, big endian.
	PUT64(evbuf, events);

	// Step 1.  HS := HMAC-SHA-1(K, C)
	mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), key,
	    keylen, evbuf, 8, hash);

	// Step 2. Sbits := DT(HS)
	s = DT(hash);

	// Step 3. D := Snum % 10^(digit)
	for (m = 1; digits; digits--) {
		m *= 10;
	}
	snprintf(buf, bufsz, "%06d", s % m);
}

void
otptest(void)
{
	// 20 byte test secret - 160 bits
	char     buf[8];
	char *   secret   = "12345678901234567890";
	uint64_t ev       = 0;
	char *   good[10] = {
                // known answers from RFC 4226, Appendix D.
                "755224",
                "287082",
                "359152",
                "969429",
                "338314",
                "254676",
                "287922",
                "162583",
                "399871",
                "520489",
	};
	for (ev = 0; ev < 10; ev++) {
		otp(buf, sizeof(buf), (uint8_t *) secret, strlen(secret), 6,
		    ev);
		if (strcmp(buf, good[ev]) != 0) {
			fprintf(stderr, "Failed OTP self test: %d %s != %s\n",
			    (int) ev, buf, good[ev]);
			exit(1);
		}
	}
}
