// Copyright 2022 Eugen Hartmann. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>
#include "tester.h"

int main(int argc, char* argv[])
{
  int primeLengthInBits = 512;
  int generator = 2;

  try {
    if (argc > 1) {
      primeLengthInBits = std::stoi(argv[1]);
    }
    if (argc > 2) {
      generator = std::stoi(argv[2]);
    }
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    return 1;
  }
 
  std::cout << "USAGE: diffie-hellman-cpp [prime_length_in_bits] [generator]" << std::endl;
  std::cout << "PRIME LENGTH (bits): " << primeLengthInBits << std::endl;
  std::cout << "GENERATOR: " << generator << std::endl;  

  Tester{primeLengthInBits, generator}.Run();

  return 0;
}
