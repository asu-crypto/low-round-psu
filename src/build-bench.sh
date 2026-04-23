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

cmake -S . -B "$SCRIPT_FPATH/build" -DCMAKE_BUILD_TYPE=Release -DBUILD_BENCH=ON -DBUILD_TESTS=OFF
cmake --build "$SCRIPT_FPATH/build" -- -j$(nproc)