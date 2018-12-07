set(LIBRARY_SOURCES
		felica
		freefare
		freefare_internal
		mad
		mifare_application
		mifare_classic
		mifare_desfire
		mifare_desfire_aid
		mifare_desfire_crypto
		mifare_desfire_error
		mifare_desfire_key
		mifare_key_deriver
		mifare_ultralight
		ntag21x
		ntag21x_error
		tlv
		../contrib/libutil/hexdump
		)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_library(freefare SHARED ${LIBRARY_SOURCES})
target_link_libraries(freefare ${LIBS})

set(installheaders freefare.h)
install(FILES ${installheaders} DESTINATION ${INCLUDE_INSTALL_DIR}/freefare COMPONENT headers)

if(WIN32)
  # On Windows the shared (runtime) library should be either in the same
  # directory as the excutables or in the path, we add it to same directory
  install(TARGETS freefare RUNTIME DESTINATION bin COMPONENT libraries)

  # At compile time we need the .LIB file, we place it in the lib directory
  install(TARGETS freefare ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT headers)
else(WIN32)
  install(TARGETS freefare LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT libraries)
endif(WIN32)
