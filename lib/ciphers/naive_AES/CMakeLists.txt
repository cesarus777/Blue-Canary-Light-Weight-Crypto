set(CIPHER_NAME naive_AES)
if(NOT "${CIPHER_NAME}" IN_LIST "${CIPHER_LIST}")
  set(CIPHER_LIST ${CIPHER_NAME} ${CIPHER_LIST} CACHE INTERNAL "")
endif()

set(sources
  cipher.c
)

add_library(${CIPHER_NAME} STATIC ${sources})
