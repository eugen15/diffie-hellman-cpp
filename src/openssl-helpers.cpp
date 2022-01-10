// Copyright 2022 Eugen Hartmann. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.


#include <tuple>
#include <openssl/err.h>

#include "openssl-helpers.h"

namespace OpenSSL {

std::tuple<unsigned long, std::string> GetLastError() {
  unsigned long lastError = ERR_peek_last_error();
  if (lastError == 0) {
    return {0, ""};
  }
  char errorString[256];
  ERR_error_string_n(lastError, errorString, sizeof(errorString));
  return {lastError, errorString};
}

std::string GetLastErrorString() {
  return std::get<1>(GetLastError());
}

BIGNUM* ConvertHexToBigNum(std::string_view hexBigNum) {
  BIGNUM* bn = nullptr;
  if (!BN_hex2bn(&bn, hexBigNum.data())) {
    return nullptr;
  }
  return bn;
}

std::string ConvertBigNumToHex(const BIGNUM* bigNum) {
  char* tmpHexBigNum = BN_bn2hex(bigNum);
  if (!tmpHexBigNum) {
    return std::string();
  }
  std::string hexBigNum(tmpHexBigNum);
  OPENSSL_free(tmpHexBigNum);
  return hexBigNum;
}

}
