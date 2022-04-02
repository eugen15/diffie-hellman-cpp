// Copyright 2022 Eugen Hartmann. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <string_view>

#include "ec-diffie-hellman.h"

class ECDHTester final {
public:
  // Construct an instance, sets the prime length and generator number.
  ECDHTester(std::string_view curveName);

  // Runs predefined tests.
  void Run();

  // Show supported curves.
  static void ShowSupportedCurves();

private:

  Result DoTest(ECDiffieHellman* alice, ECDiffieHellman* bob);

  static void PrintCurvesInfo(const std::map<std::string, ECDiffieHellman::CurveInfo>& curves);
  static void PrintCurveInfo(const ECDiffieHellman::CurveInfo& curveInfo);

  std::string curveName_;
};