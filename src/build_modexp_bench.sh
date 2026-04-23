#!/bin/bash

# Build script to compile and run the OpenSSL vs GMP modular exponentiation benchmark

echo "Building the modexp comparison benchmark..."

cd /home/lpiske/low-round-psu/src

# Clean and create build directory
rm -rf build
mkdir -p build
cd build

# Configure with BUILD_BENCH=ON to build benchmarks
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_BENCH=ON

# Build the specific benchmark
make modexp_comparison_bench -j$(nproc)

echo "Build complete. You can run the benchmark with:"
echo "./modexp_comparison_bench [modexp][comparison]"
echo ""
echo "Available test tags:"
echo "  [modexp][comparison]          - Standard comparison (2^12 ops, 512-bit modulus, 128-bit exponents)" 
echo "  [modexp][comparison][large]   - Large comparison (2^10 ops, 1024-bit modulus, 256-bit exponents)"
echo "  [modexp][single][comparison]  - Single operation comparison with different exponent sizes"
echo ""
echo "Example usage:"
echo "  ./modexp_comparison_bench"
echo "  ./modexp_comparison_bench [modexp][comparison]"
echo "  ./modexp_comparison_bench --benchmark-samples 10"