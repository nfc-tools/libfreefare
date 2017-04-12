# TODO locate using pkg-config for linux/bsd

#set(LIBNFC_INCLUDE_DIRS "")
#set(LIBNFC_LIBRARIES "")
set(LIBNFC_INSTALL_DIR $ENV{PROGRAMFILES}/libnfc CACHE PATH "libnfc installation directory")

message("libnfc install dir: " ${LIBNFC_INSTALL_DIR})

find_path(LIBNFC_INCLUDE_DIRS NAMES nfc/nfc.h PATHS ${LIBNFC_INSTALL_DIR}/include)
message("libnfc include dir found:  " ${LIBNFC_INCLUDE_DIRS})

find_library(LIBNFC_LIBRARIES nfc PATHS ${LIBNFC_INSTALL_DIR}/lib)
message("libnfc library found:  " ${LIBNFC_LIBRARIES})

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LIBNFC DEFAULT_MSG
  LIBNFC_INCLUDE_DIRS
  LIBNFC_LIBRARIES
)
MARK_AS_ADVANCED(LIBNFC_INCLUDE_DIRS LIBNFC_LIBRARIES)
