// Copyright 2022 Eugen Hartmann. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <string_view>

#include "diffie-hellman.h"

class DHTester final {
 public:
  // Construct an instance, sets the prime length and generator number.
  DHTester(int primeLengthInBits, int generator);

  // Runs predefined tests.
  void Run();

 private:
  Result DoTest(DiffieHellman* alice, DiffieHellman* bob);
  static void PrintObjectLength(std::string_view comment,
    std::tuple<int, int> bitsBytes, const std::string& hex);

  int primeLengthInBits_ = 512;
  int generator_ = 2;
};