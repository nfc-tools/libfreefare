set(EXAMPLES-SOURCES
	felica-lite-dump
	felica-read-ndef
        mifare-classic-format
        mifare-classic-read-ndef
        mifare-classic-write-ndef
        mifare-desfire-access
        mifare-desfire-create-ndef
        mifare-desfire-format
        mifare-desfire-info
        mifare-desfire-read-ndef
        mifare-desfire-write-ndef
        mifare-desfire-ev1-configure-ats
        mifare-desfire-ev1-configure-default-key
        mifare-desfire-ev1-configure-random-uid
        mifare-ultralight-info
        mifare-ultralightc-diversify
        ntag-detect
        ntag-removeauth
        ntag-setauth
        ntag-write
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../libfreefare)

# Examples
foreach(source ${EXAMPLES-SOURCES})
  add_executable(${source} ${source}.c)
  target_link_libraries(${source} freefare)
  install(TARGETS ${source} RUNTIME DESTINATION bin COMPONENT examples)
endforeach(source)
