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

#include <stddef.h>
#include <stdint.h>

#ifndef BASE32_H
#define BASE32_H

// Base32 implementation, needed for Oath.  This is specified by RFC 4648.
// The alphabet is compromised of groups of 5 bits at a time, and avoids
// letters that may be easily mistyped.

// Decodes from base32.  If the decode fails, returns 0.  Otherwise
// returns the number of bytes decoded.  Check for overflow by
// comparing result against passed in buffer size.
extern size_t base32_decode(const char *, size_t, uint8_t *, size_t);

// Encodes into base32.  Same size_t return result semantic as above,
// but never returns a failure.  This never encodes padding, as our
// use cases do not require it.
extern size_t base32_encode(const uint8_t *, size_t, char *, size_t);

#endif // BASE32_H
