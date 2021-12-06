#!/bin/sh

src_dir="$(readlink -f $(dirname $0)/..)"
build_dir="${src_dir}/build"
install_dir="${src_dir}/install"
compiler="/usr/bin/cc"

USAGE="Usage info: install.sh [OPTION(s)]
Options:
    -h, --help                Show this help
    -c <compiler>             Specify compiler to use. /usr/bin/cc is used by default
    -u, --use-cache           Use existing build cache. Cache from previous build wouldn't be deleted
    -S, --src-dir     <path>  Path to sources directory
    -B, --build-dir   <path>  Path to build directory
    -I, --install-dir <path>  Path to install direcory
    *                         All other options are passed directly to cmake"

while [ -n "$1" ]; do
  case "$1" in
    -u|--use-cache)
      using_build_cache="1"
      ;;
    -S|--src-dir)
      src_dir="$2"
      shift
      ;;
    -B|--build-dir)
      build_dir="$2"
      shift
      ;;
    -I|--install-dir)
      install_dir="$2"
      shift
      ;;
    -h|--help)
      echo "$USAGE"
      exit 0
      ;;
    -c)
      compiler="$2"
      shift
      ;;
    *)
      additional_cmake_properties="${additional_cmake_properties} $1"
      ;;
  esac
  shift
done

if [ -z "$using_build_cache" ]; then
  rm -rf $build_dir $install_dir || exit $?
fi

mkdir -p $build_dir || exit $?

cmake_task="-B ${build_dir} -S ${src_dir} ${additional_cmake_properties}"

#TODO: find ninja more elegant
if [ -x /usr/bin/ninja ]; then
  cmake_generator="-GNinja"
fi

build_task="${build_dir}"
install_task="-DCMAKE_INSTALL_PREFIX=/ -P ${build_dir}/cmake_install.cmake"

if [ -z "${using_build_cache}" ]; then
  CC="${compiler}" cmake ${cmake_generator} ${cmake_task} || exit $?
fi

cmake --build ${build_task} || exit $?
DESTDIR=${install_dir} cmake ${install_task} || exit $?

exit 0
