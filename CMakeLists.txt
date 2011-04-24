# $Id$
project(libfreefare C)
cmake_minimum_required(VERSION 2.6)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/modules/")

add_definitions("-std=c99")

find_package(LIBNFC REQUIRED)
find_package(OpenSSL REQUIRED)

IF(WIN32)
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/config_windows.h.cmake ${CMAKE_CURRENT_SOURCE_DIR}/config.h)
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32)
  find_library(WINSOCK_LIB libws2_32.a)
  set(LIBS ${LIBS} ${WINSOCK_LIB})
ENDIF(WIN32)

if(MINGW)
  # force MinGW-w64 in 32bit mode
  add_definitions("-m32")
  set(CMAKE_SHARED_LINKER_FLAGS -m32)
  set(CMAKE_EXE_LINKER_FLAGS -m32)
endif(MINGW)

message("CMAKE_C_FLAGS: " ${CMAKE_C_FLAGS})
message("CMAKE_SHARED_LINKER_FLAGS: " ${CMAKE_SHARED_LINKER_FLAGS})

include_directories(${LIBNFC_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
set(LIBS ${LIBS} ${LIBNFC_LIBRARIES} ${OPENSSL_LIBRARIES})

if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  message("CMAKE_INSTALL_PREFIX not defined")
  set(CMAKE_INSTALL_PREFIX "c:/projects/EVENT/install") # TODO
endif(NOT DEFINED CMAKE_INSTALL_PREFIX)

if(DEFINED CMAKE_INSTALL_LIBDIR)
  set(libdir ${CMAKE_INSTALL_LIBDIR})
else(DEFINED CMAKE_INSTALL_LIBDIR)
  set(CMAKE_INSTALL_LIBDIR lib)
  set(libdir ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
endif(DEFINED CMAKE_INSTALL_LIBDIR)

if(DEFINED INCLUDE_INSTALL_DIR)
  set(includedir ${INCLUDE_INSTALL_DIR})
else(DEFINED INCLUDE_INSTALL_DIR)
  set(INCLUDE_INSTALL_DIR include)
  set(includedir ${CMAKE_INSTALL_PREFIX}/${INCLUDE_INSTALL_DIR})
endif(DEFINED INCLUDE_INSTALL_DIR)

if(NOT DEFINED SHARE_INSTALL_PREFIX)
  set(SHARE_INSTALL_PREFIX share)
endif(NOT DEFINED SHARE_INSTALL_PREFIX)

add_subdirectory(libfreefare)
add_subdirectory(examples)
