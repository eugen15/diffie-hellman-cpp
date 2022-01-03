// Copyright 2022 Eugen Hartmann. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base-helpers.h"

static int GetHexValue(unsigned char hexDigit)
{
  static constexpr char hexValues[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  };
  return hexValues[hexDigit];
}

namespace Base {

std::string ConvertDataToHex(std::string_view data) {
  static const char hexDigits[] = "0123456789ABCDEF";

  std::string hex;
  hex.reserve(data.size() * 2);

  for (unsigned char c : data) {
    hex.push_back(hexDigits[c >> 4]);
    hex.push_back(hexDigits[c & 15]);
  }

  return hex;
}

Result ConvertHexToData(std::string_view hex, std::string* data) {
  // Must be an even number!
  if (hex.size() & 1) {
    return Result{Result::Fail, "The hex string size must be an even number."};
  }

  data->clear();
  data->reserve(hex.size() / 2);

  auto it = hex.begin();
  while (it != hex.end()) {
    int hi = GetHexValue(*it++);
    int lo = GetHexValue(*it++);
    if (hi == -1 || lo == -1) {
      return Result{Result::Fail, "Bad hex digit."};
    }
    data->push_back(hi << 4 | lo);
  }

  return Result{Result::Success};
}

}
