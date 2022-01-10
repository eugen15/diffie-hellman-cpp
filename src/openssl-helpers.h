// Copyright 2022 Eugen Hartmann. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <string>
#include <string_view>

#include <openssl/bn.h>
#include <openssl/dh.h>

#include "result.h"
#include "base-helpers.h"

namespace OpenSSL {

// BN_free
// "If a is NULL, nothing is done."
// https://www.openssl.org/docs/man3.0/man3/BN_free.html

// DH_free
// "If dh is NULL nothing is done."
// https://www.openssl.org/docs/man3.0/man3/DH_free.html

// Gets current thread libressl last error (both numberic and text).
std::tuple<unsigned long, std::string> GetLastError();
// Gets current thread libressl last text error message.
std::string GetLastErrorString();

// Converts a hex string to BIGNUM.
BIGNUM* ConvertHexToBigNum(std::string_view hexBigNum);

// Converts BIGNUM to a hex string.
// Returns an empty string if convertion fails.
std::string ConvertBigNumToHex(const BIGNUM* bigNum);

}
