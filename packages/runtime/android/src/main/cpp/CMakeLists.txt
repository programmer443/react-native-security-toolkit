cmake_minimum_required(VERSION 3.13)
project(rnsecuritytoolkit)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(rnsecuritytoolkit SHARED rnsec_native.cpp)

# Align load segments to 16 KB.
#
# Android 15 introduced 16 KB memory pages, and Google Play requires 16 KB
# support for apps targeting Android 15 and above. NDK r28 aligns by default;
# r27 and earlier do not, and this library is pinned to r27 to match the React
# Native template. Setting the flag explicitly makes the result correct on any
# NDK rather than depending on which one the build machine happens to use.
#
# See https://developer.android.com/guide/practices/page-sizes
target_link_options(rnsecuritytoolkit PRIVATE "-Wl,-z,max-page-size=16384")

target_link_libraries(rnsecuritytoolkit log)
