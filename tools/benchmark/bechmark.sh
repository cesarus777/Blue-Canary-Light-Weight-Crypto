#!/bin/sh

src_dir="$(readlink -f $(dirname $0)/../..)"

${src_dir}/tools/install.sh

for benchmark in ${src_dir}/install/benchmark/*; do
  benchmark_name="$(basename ${benchmark})"
  echo ${benchmark_name} >> ${src_dir}/benchmark.log
  ${benchmark} >> ${src_dir}/benchmark.log
done
