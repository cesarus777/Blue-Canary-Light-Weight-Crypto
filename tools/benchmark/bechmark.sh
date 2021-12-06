#!/bin/sh

src_dir="$(readlink -f $(dirname $0)/../..)"
benchmark_log="${src_dir}/benchmark.log"

for cc in "gcc" "clang"; do
  ${src_dir}/tools/install.sh -c "${cc}" || exit $?
  echo "$(date) ${cc}" >> ${benchmark_log}
  for benchmark in ${src_dir}/install/benchmark/*; do
    benchmark_name="$(basename ${benchmark})"
    echo -n ${benchmark_name} >> ${benchmark_log}
    ${benchmark} >> ${benchmark_log}
  done
done
