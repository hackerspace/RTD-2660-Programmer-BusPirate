cmake_minimum_required(VERSION 3.6)
project(RTD_2660_Programmer)

set(CMAKE_CXX_STANDARD 11)

option (WITH_BITBANG "compile with usb bitbang i2c" OFF)

add_subdirectory ("RTD Programmer")

