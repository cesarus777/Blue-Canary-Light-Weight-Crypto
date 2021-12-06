set(OPT_LEVELS O0 O1 O2 O3 Os)

foreach(CIPHER IN LISTS CIPHER_LIST)
  set(BENCHMARK_CMD "benchmark_${CIPHER}")

  foreach(OPT_LEVEL IN LISTS OPT_LEVELS)
    set(BENCHMARK_CMD_OPT "${BENCHMARK_CMD}_${OPT_LEVEL}")
    add_executable("${BENCHMARK_CMD_OPT}"
                   "${CMAKE_CURRENT_SOURCE_DIR}/benchmark.c")
    target_compile_options("${BENCHMARK_CMD_OPT}" PUBLIC ${CMAKE_C_FLAGS}
                                                         -${OPT_LEVEL})
    target_link_libraries("${BENCHMARK_CMD_OPT}" "${CIPHER}")

    install(TARGETS ${BENCHMARK_CMD_OPT} RUNTIME DESTINATION benchmark
                                                 COMPONENT benchmark)
  endforeach()
endforeach()
