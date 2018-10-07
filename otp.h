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

#ifndef OTP_H
#define OTP_H

// One time password calculation support.

#include <stddef.h>
#include <stdint.h>

// This provides an RFC 4226 compliant OTP.  It only supports SHA-1
// based HMAC.  The OTP calculation can be used for TOTP by using
// counter that is time derived (time periods since UNIX epoch)
// instead of a counter.

// Caller is expected to keep state, check for adjacent events,
// and limit failed attempts.

// This generates an OTP authentication.  Only SHA-1 is supported, but
// we don't know of any OTP implementations that use or support other
// hash algorithms.
extern void otp(char *, size_t, const unsigned char *, size_t, int, uint64_t);

// otptest just runs an internal self test of the OTP algorithm against
// known answers from RFC 4226.  If it fails, it causes the program to exit.
extern void otptest(void);

#endif // OTP_H
