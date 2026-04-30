#!/bin/sh

SCRIPT_FPATH="$(cd "$(dirname "$0")" && pwd)"

# Check for --clean flag
CLEAN_BUILD=false
for arg in "$@"; do
    case $arg in
        --clean)
            CLEAN_BUILD=true
            ;;
    esac
done

# Only remove build directory if --clean flag is provided
if [ "$CLEAN_BUILD" = true ]; then
    echo "Cleaning build directory..."
    rm -rf "$SCRIPT_FPATH/build"
fi

mkdir -p "$SCRIPT_FPATH/build"

cd "$SCRIPT_FPATH/build"
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_BENCH=OFF -DBUILD_TESTS=OFF
make iblt_interface -j$(nproc)