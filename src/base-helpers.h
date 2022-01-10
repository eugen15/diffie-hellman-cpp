// Copyright 2022 Eugen Hartmann. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <string>
#include <string_view>
#include <type_traits>

#include "result.h"

namespace Base {

/*template <auto fn>
struct DeleterFromFn {
  template <typename T>
  constexpr void operator()(T* arg) const {
    fn(arg);
  }
};*/

template <auto fn>
using DeleterFromFn = std::integral_constant<decltype(fn), fn>;

// Converts binary data to a hex string.
std::string ConvertDataToHex(std::string_view data);

// Converts a hex string to binary data.
Result ConvertHexToData(std::string_view hex, std::string* data);

}
