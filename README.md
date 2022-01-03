
# Diffie-Hellman CPP

The project goal is to write a C++ Diffie-Hellman implementation compatible with LibreSSL/OpenSSL. There is no any practical profit. I do it just for fun. By compatibility I mean exchanging p, g and the public key without any issues. Then, deriving a correct shared secret on both sides. Initially, I wanted to write my own big number implemented. Unfortunately, it would take too much time. So, for beginning, I decided to use boost cpp_int. It is obviously that the compatibility should be tested. I use LibreSSL for that. I never touched it earlier so decided to play with it.

## Source code
See below for the main classes.
* ``DiffieHellman``: The interface for Diffie-Hellman implementations. Also, it provides the factory method to create an appropriate instance.
* ``DiffieHellmanLibreSSLDH``: The typical Diffie-Hellman implementation. It is based on LibreSSL DH functions.
* ``DiffieHellmanLibreSSLBN``: The intermediate implementation which is based on LibreSSL BIGNUM without the DH functions.
* ``DiffieHellmanBoost``: The C++ implementation uses boost::multiprecision::cpp_int for big number operations.
* ``Tester``: The tester class.

## Building
The project uses ``std::format``, ``using enum`` and other modern C++ features so you need latest compilers for it. See the links below.

* https://en.cppreference.com/w/cpp/compiler_support
* https://docs.microsoft.com/en-us/cpp/overview/visual-cpp-language-conformance
* https://clang.llvm.org/cxx_status.html

You also need CMake, LibreSSL and Boost C++ (headers only). You have to compile LibreSSL. If you do not want to use LibreSSL, you can try OpenSSL 1.x.x. The DH and BIGNUM API should be compatible.  In this case, you may need to change linked library names in the project CMakeLists.txt. Although, anyway, I cannot guarantee it will work.

### Windows
VS 2019 v16.10 & v16.11 or later is required. Personally, I use VS 2022. The download link is here https://visualstudio.microsoft.com/vs/community/.

CMake is available as a part of VS 2022 installation. In my case it is located in the following folder: ``C:/Program Files/Microsoft Visual Studio/2022/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/``. Install CMake separately https://cmake.org/ if your VS does not include it. 

Download the latest LibreSSL https://www.libressl.org/. Go to the root of the unpacked LibreSSL and execute the following commands:

```
mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=your_libressl_installation_folder
cmake --build . --config Debug
cmake --install . --config Debug
```
(you can choose either Debug or Release).

Download and unpack the latest Boost C++ if you do not have it on your machine. You can compile the library if you like but it is not necessary.

Download the project, go to the root and run the following commands:
```
mkdir build
cd build
cmake .. -DINCLUDE_DIRS="your_boost_root_folder;your_libressl_installation_folder\include" -DLIBRARY_DIRS="your_libressl_installation_folder\lib"
cmake --build . --config Debug
```
(again, choose either Debug or Release according to your LibreSSL build).

### Ubuntu 20.x.x
If CMake is not installed, run the following command: ``sudo apt install cmake``.

Download the latest LibreSSL https://www.libressl.org/. Go to the root of the unpacked LibreSSL and execute the following commands:
```
cmake .. -DCMAKE_INSTALL_PREFIX=your_libressl_installation_dir_prefix
cmake --build .
cmake --install .
```

If you do not have Boost C++ installed on your machine, you have the following options:
* Install the whole Boost C++ : ``sudo apt install libboost-all-dev``
* Install boost::multiprecision only (the package name may be different): ``sudo apt install libboost-mpi1.71-dev``
* Download and unpack Boost C++ to access its headers.

You have to install Clang 14 to compile the project (see https://apt.llvm.org/ for updates if the instruction below does not work).
* Add the following lines to your /etc/apt/sources.list:
``deb http://apt.llvm.org/focal/ llvm-toolchain-focal main``
``deb-src http://apt.llvm.org/focal/ llvm-toolchain-focal main``
* Add signatures for these repos (otherwise apt-get update will complain in the next step):
``wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key|sudo apt-key add -``
* Run ``sudo apt update`` to add these repos to the apt.
* Install Clang 14.
``sudo apt install clang-14``
``sudo apt install libc++-14-dev libc++abi-14-dev``
* Make sure now Clang 14 is used by CMake.
``export CXX=clang++-14``

Download the project, go to the root and run the following commands:

```
mkdir build
cd build
cmake .. -DINCLUDE_DIRS="your_boost_root_folder;your_libressl_installation_dir_prefix\include" -DLIBRARY_DIRS="your_libressl_installation_dir_prefix\lib"
cmake --build .
```
(you might not need to specify the Boost C++ root folder if the library is installed into your system standard location).

## Testing
Run the program to start the tests. You can explicitly specify the prime length in bits and the generator. See examples below:
* ``diffie-hellman-cpp`` (the prime length is 256; the generator is 2)
* ``diffie-hellman-cpp 512 5`` (the prime length is 512; the generator is 5)

The following tests are performed:
* Alice LibreSSL DH <-> Bob LibreSSL DH
* Alice LibreSSL DH <-> Bob LibreSSL BIGNUM
* Alice LibreSSL BIGNUM <-> Bob LibreSSL DH
* Alice LibreSSL DH <-> Bob Boost cpp_int
* Alice Boost cpp_int <-> Bob LibreSSL DH


