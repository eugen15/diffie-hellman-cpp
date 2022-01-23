// Copyright 2022 Eugen Hartmann. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <string>
#include <string_view>

#include <openssl/bn.h>
#include <openssl/dh.h>

namespace LibreSSL {

// BN_free
// "If a is a NULL pointer, no action occurs."
// https://man.openbsd.org/BN_new.3

// DH_free
// "If dh is a NULL pointer, no action occurs."
// https://man.openbsd.org/DH_new.3


// BM_CTX_free
// "If c is a NULL pointer, no action occurs."
// https://man.openbsd.org/BN_CTX_new.3

// Gets current thread libressl last error (both numberic and text).
std::tuple<unsigned long, std::string> GetLastError();
// Gets current thread libressl last text error message.
std::string GetLastErrorString();

// Converts a hex string to BIGNUM.
// Returns nullptr if convertion fails.
BIGNUM* ConvertHexToBigNum(std::string_view hexBigNum);

// Converts BIGNUM to a hex string.
// Returns an empty string if convertion fails.
std::string ConvertBigNumToHex(const BIGNUM* bigNum);

}
