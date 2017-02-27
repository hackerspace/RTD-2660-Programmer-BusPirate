cmake_minimum_required (VERSION 3.6)

set (PROGRAMMER_SRC main.cpp crc.cpp gff.cpp)

if (WITH_BITBANG)
	set (PROGRAMMER_SRC ${PROGRAMMER_SRC} i2c.cpp)
	else()
	set (PROGRAMMER_SRC ${PROGRAMMER_SRC} i2cnative.cpp)
endif()


add_definitions ("-DBUILD_WITH_CMAKE")

add_executable (programmer ${PROGRAMMER_SRC})