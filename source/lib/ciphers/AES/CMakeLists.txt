set(AES-sources
  decrypt.c
  encrypt.c
)

add_library(AES STATIC ${AES-sources})
