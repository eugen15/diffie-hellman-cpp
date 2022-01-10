cmake_minimum_required(VERSION 3.15)

project(diffie-hellman-cpp)

message(STATUS "Use -DUSE_OPENSSL=ON to compile with OpenSSL 3 support instead of LibreSSL.")
message(STATUS "Use -DINCLUDE_DIRS=\"path1;path2;path3\" to specify additional include directories.")
message(STATUS "Use -DLIBRARY_DIRS=\"path1;path2;path3\" to specify additional library directories.")

foreach(INCLUDE_DIR IN LISTS INCLUDE_DIRS)
  include_directories(${INCLUDE_DIR})
endforeach()

foreach(LIBRARY_DIR IN LISTS LIBRARY_DIRS)
  link_directories(${LIBRARY_DIR})
endforeach()

if (WIN32)
  if((NOT CMAKE_CXX_COMPILER_ID STREQUAL "MSVC") OR MSVC_VERSION LESS 1929)
    message(
      "-------------------------------------\n"
      "VS 2019 v16.10 & v16.11 or later is required because the project uses std::format. "
      "See: https://devblogs.microsoft.com/cppblog/msvc-cpp20-and-the-std-cpp20-switch.\n"
      "-------------------------------------")
    message(FATAL_ERROR "See above for details.")
  endif()

  add_compile_options("/std:c++latest")

  option(USE_STATIC_MSVC_RUNTIMES "Use /MT instead of /MD in MSVC" OFF)
  if(USE_STATIC_MSVC_RUNTIMES)
    add_compile_options(
      $<$<CONFIG:>:/MT>
      $<$<CONFIG:Debug>:/MTd>
      $<$<CONFIG:Release>:/MT>
    )
  endif()
else()
  if ((NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang") OR CLANG_VERSION_MAJOR LESS 14)
      message(
        "-------------------------------------\n"
        "Clang 14 or later is required because the project uses std::format. "
        "https://en.cppreference.com/w/cpp/compiler_support\n"
        "-------------------------------------")
      message(FATAL_ERROR "See above for details.")      
  endif()
  set(CMAKE_CXX_STANDARD 20)
  set(CMAKE_CXX_STANDARD_REQUIRED True)
  if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_compile_options("-stdlib=libc++")
    add_link_options("-stdlib=libc++")
  endif()
endif()

set(SOURCES
  ${SOURCES}
  src/base-helpers.cpp
  src/diffie-hellman.cpp
  src/diffie-hellman-boost.cpp
  src/tester.cpp
  src/main.cpp
)

set(HEADERS
  ${HEADERS}
  src/result.h
  src/base-helpers.h
  src/diffie-hellman.h
  src/diffie-hellman-boost.h
  src/tester.h
)

option(USE_OPENSSL "Use OpenSSL 3.x.x instead of LibreSSL 3.x.x" OFF)
if(USE_OPENSSL)
  set(SOURCES
    ${SOURCES}
    src/openssl-helpers.cpp
    src/diffie-hellman-openssl.cpp
  )
  set(HEADERS
    ${HEADERS}
    src/openssl-helpers.h
    src/diffie-hellman-openssl.h
  )
  add_definitions(-DUSE_OPENSSL)
else()
  set(SOURCES
    ${SOURCES}
    src/libressl-helpers.cpp
    src/diffie-hellman-libressl-dh.cpp
    src/diffie-hellman-libressl-bn.cpp
  )
  set(HEADERS
    ${HEADERS}
    src/libressl-helpers.h
    src/diffie-hellman-libressl-dh.h
    src/diffie-hellman-libressl-bn.h
  )
endif()


add_executable(${CMAKE_PROJECT_NAME} ${SOURCES} ${HEADERS})

if(USE_OPENSSL)
  if (MSVC)
    target_link_libraries(${CMAKE_PROJECT_NAME} libcrypto)
  else()
  endif()
else()
  if (MSVC)
    target_link_libraries(${CMAKE_PROJECT_NAME} crypto-47 Bcrypt Ws2_32)
  else()
    target_link_libraries(${CMAKE_PROJECT_NAME} crypto pthread)
  endif()
endif()
