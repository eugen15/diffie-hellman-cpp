// Copyright 2022 Eugen Hartmann. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>
#include <iomanip>

#include "dh-tester.h"
#include "ecdh-tester.h"

void ShowUsageHint() {
  static const int firstColumnWidth = 37;

#if defined(USE_OPENSSL)
  std::cout << "Compiled with the OpenSSL support." << std::endl;
#else
  std::cout << "Compiled with the LibreSSL support." << std::endl;
#endif

  std::cout << "USAGE: diffie-hellman-cpp {dh [PRIME_LENGTH_IN_BITS] "
    "[GENERATOR] | ecdh [CURVE_NAME] | ecdh-curves}" << std::endl;
  std::cout << "EXAMPLES:" << std::endl;
  std::cout << std::left << std::setw(firstColumnWidth) << "  diffie-hellman-cpp ecdh"
    << "ECDH key exchange with the secp384r1 curve." << std::endl;
  std::cout << std::left << std::setw(firstColumnWidth) << "  diffie-hellman-cpp ecdh secp521r1"
    << "ECDH key exchange with the secp521r1 curve." << std::endl;
  std::cout << std::left << std::setw(firstColumnWidth) << "  diffie-hellman-cpp ecdh-curves"
    << "Enumerates supported ECDH curves." << std::endl;
  std::cout << std::left << std::setw(firstColumnWidth) << "  diffie-hellman-cpp dh"
    << "DH key exchange with a 512 bit prime; the generator is 2." << std::endl;
  std::cout << std::left << std::setw(firstColumnWidth) << "  diffie-hellman-cpp dh 512 5"
    << "DH key exchange with a 512 bit prime; the generator is 5." << std::endl;
  std::cout << std::left << std::setw(firstColumnWidth) << "  diffie-hellman-cpp dh 256"
    << "DH key exchange with a 256 bit prime (too small for OpenSSL!)." << std::endl;
}

int main(int argc, char* argv[]) {
  ShowUsageHint();

  if (argc > 1) {
    if (std::string_view(argv[1]) == "ecdh-curves") {
      // Show supported ECDH curves.
      ECDHTester::ShowSupportedCurves();
    } else if (std::string_view(argv[1]) == "ecdh") {
      // Test ECDH key exchange.
      std::string curveName{"secp384r1"};
      if (argc > 2) {
        curveName = argv[2];
      }      

      ECDHTester::ECDHTester(curveName).Run();

    } else if (std::string_view(argv[1]) == "dh") {
      // Test DH exchange.
      try {
        int primeLengthInBits = (argc > 2) ? std::stoi(argv[2]) : 512;
        int generator = (argc > 3) ? std::stoi(argv[3]) : 2;

        DHTester{primeLengthInBits, generator}.Run();

      } catch (const std::exception& e) {
        std::cout << e.what() << std::endl;
        return 1;
      }

    }
  }

  return 0;
}
