set(CIPHER_NAME AES)
if(NOT "${CIPHER_NAME}" IN_LIST "${CIPHER_LIST}")
  set(CIPHER_LIST ${CIPHER_NAME} ${CIPHER_LIST} CACHE INTERNAL "")
endif()
message("-- AES cipher registered")

set(sources
  cipher.c
)

add_library(${CIPHER_NAME} STATIC ${sources})
