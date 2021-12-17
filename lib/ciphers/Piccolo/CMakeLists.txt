set(CIPHER_NAME Piccolo)
if(NOT "${CIPHER_NAME}" IN_LIST "${CIPHER_LIST}")
  set(CIPHER_LIST
      ${CIPHER_NAME} ${CIPHER_LIST}
      CACHE INTERNAL "")
endif()

set(sources piccolo.c)

add_library(${CIPHER_NAME} STATIC ${sources})
target_compile_definitions("${CIPHER_NAME}" PUBLIC "PICCOLO=128")

foreach(OPT_LEVEL IN LISTS OPT_LEVELS)
  set(CIPHER_LIB_NAME "${CIPHER_NAME}_${OPT_LEVEL}")
  add_library(${CIPHER_LIB_NAME} STATIC ${sources})
  target_compile_definitions("${CIPHER_LIB_NAME}" PUBLIC "PICCOLO=128")
  target_compile_options("${CIPHER_LIB_NAME}" PUBLIC ${CMAKE_C_FLAGS}
                                                     -${OPT_LEVEL})
endforeach()
