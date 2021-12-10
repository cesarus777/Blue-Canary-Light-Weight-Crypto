foreach(CIPHER IN LISTS CIPHER_LIST)
  set(BENCHMARK_CMD "benchmark_${CIPHER}")

  foreach(OPT_LEVEL IN LISTS OPT_LEVELS)
    set(BENCHMARK_CMD_OPT "${BENCHMARK_CMD}_${OPT_LEVEL}")
    add_executable("${BENCHMARK_CMD_OPT}"
                   "${CMAKE_CURRENT_SOURCE_DIR}/benchmark.c")
    target_link_libraries("${BENCHMARK_CMD_OPT}" "${CIPHER}_${OPT_LEVEL}")

    install(TARGETS ${BENCHMARK_CMD_OPT} RUNTIME DESTINATION benchmark
                                                 COMPONENT benchmark)
  endforeach()
endforeach()
