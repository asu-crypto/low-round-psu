#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <array>
#include "../utils.hpp"
#include "cryptoTools/Common/block.h"

using osuCrypto::block;

TEST_CASE("split block (n=4, middle=2)", "[split_block]") {
    block x = block(0, 0b1110);
    size_t n = 4;
    size_t middle = 2;

    std::array<block,2> blocks;
    split_block(x, n, middle, blocks);

    REQUIRE(blocks[0] == block(0, 0b10));
    REQUIRE(blocks[1] == block(0, 0b11));

}

TEST_CASE("split block (n=4, middle=3)", "[split_block]") {
    block x = block(0, 0b1110);
    size_t n = 4;
    size_t middle = 3;

    std::array<block,2> blocks;
    split_block(x, n, middle, blocks);

    REQUIRE(blocks[0] == block(0, 0b110));
    REQUIRE(blocks[1] == block(0, 0b1));

}

TEST_CASE("split block (n=5, middle=3)", "[split_block]") {
    block x = block(0, 0b10101);
    size_t n = 5;
    size_t middle = 3;

    std::array<block,2> blocks;
    split_block(x, n, middle, blocks);

    REQUIRE(blocks[0] == block(0, 0b101));
    REQUIRE(blocks[1] == block(0, 0b10));

}

TEST_CASE("split block (n=5, middle=2)", "[split_block]") {
    block x = block(0, 0b10101);
    size_t n = 5;
    size_t middle = 2;

    std::array<block,2> blocks;
    split_block(x, n, middle, blocks);

    REQUIRE(blocks[0] == block(0, 0b01));
    REQUIRE(blocks[1] == block(0, 0b101));

}

TEST_CASE("split block (n=32, middle=16)", "[split_block]") {
    block x = block(0, 0b11000101010100011110001101111010ULL);
    size_t n = 32;
    size_t middle = 16;

    std::array<block,2> blocks;
    split_block(x, n, middle, blocks);

    REQUIRE(blocks[0] == block(0, 0b1110001101111010ULL));
    REQUIRE(blocks[1] == block(0, 0b1100010101010001ULL));

}

TEST_CASE("split block (n=32, middle=3)", "[split_block]") {
    block x = block(0, 0b11000101010100011110001101111010ULL);
    size_t n = 32;
    size_t middle = 3;

    std::array<block,2> blocks;
    split_block(x, n, middle, blocks);

    REQUIRE(blocks[0] == block(0, 0b010ULL));
    REQUIRE(blocks[1] == block(0, 0b11000101010100011110001101111ULL));

}

TEST_CASE("split block (n=32, middle=25)", "[split_block]") {
    block x = block(0, 0b11000101010100011110001101111010ULL);
    size_t n = 32;
    size_t middle = 25;

    std::array<block,2> blocks;
    split_block(x, n, middle, blocks);

    REQUIRE(blocks[0] == block(0, 0b1010100011110001101111010ULL));
    REQUIRE(blocks[1] == block(0, 0b1100010ULL));

}

TEST_CASE("split block (n=64, middle=25)", "[split_block]") {
    block x = block(0, 0b0110101000000111000011000000011001111110110001010100001110010110ULL);
    size_t n = 64;
    size_t middle = 25;

    std::array<block,2> blocks;
    split_block(x, n, middle, blocks);

    REQUIRE(blocks[0] == block(0, 0b0110001010100001110010110ULL));
    REQUIRE(blocks[1] == block(0, 0b011010100000011100001100000001100111111ULL));

}

TEST_CASE("split block (n=64, middle=32)", "[split_block]") {
    block x = block(0, 0b0110101000000111000011000000011001111110110001010100001110010110ULL);
    size_t n = 64;
    size_t middle = 32;

    std::array<block,2> blocks;
    split_block(x, n, middle, blocks);

    REQUIRE(blocks[0] == block(0, 0b01111110110001010100001110010110ULL));
    REQUIRE(blocks[1] == block(0, 0b01101010000001110000110000000110ULL));

}


TEST_CASE("split block (n=64, middle=55)", "[split_block]") {
    block x = block(0, 0b0110101000000111000011000000011001111110110001010100001110010110ULL);
    size_t n = 64;
    size_t middle = 55;

    std::array<block,2> blocks;
    split_block(x, n, middle, blocks);

    REQUIRE(blocks[0] == block(0, 0b0000111000011000000011001111110110001010100001110010110ULL));
    REQUIRE(blocks[1] == block(0, 0b011010100ULL));

}

TEST_CASE("split block with appended garbage (n=64, middle=55)", "[split_block]") {
    block x = block(1290545303681682445ULL, 0b0110101000000111000011000000011001111110110001010100001110010110ULL);
    size_t n = 64;
    size_t middle = 55;

    std::array<block,2> blocks;
    split_block(x, n, middle, blocks);

    REQUIRE(blocks[0] == block(0, 0b0000111000011000000011001111110110001010100001110010110ULL));
    REQUIRE(blocks[1] == block(0, 0b011010100ULL));

}

TEST_CASE("split block with appended garbage (n=64, middle=32)", "[split_block]") {
    block x = block(1290545303681682445ULL, 0b0110101000000111000011000000011001111110110001010100001110010110ULL);
    size_t n = 64;
    size_t middle = 32;

    std::array<block,2> blocks;
    split_block(x, n, middle, blocks);

    REQUIRE(blocks[0] == block(0, 0b01111110110001010100001110010110ULL));
    REQUIRE(blocks[1] == block(0, 0b01101010000001110000110000000110ULL));

}


TEST_CASE("split block with appended garbage (n=64, middle=25)", "[split_block]") {
    block x = block(1290545303681682445ULL, 0b0110101000000111000011000000011001111110110001010100001110010110ULL);
    size_t n = 64;
    size_t middle = 25;

    std::array<block,2> blocks;
    split_block(x, n, middle, blocks);

    REQUIRE(blocks[0] == block(0, 0b0110001010100001110010110ULL));
    REQUIRE(blocks[1] == block(0, 0b011010100000011100001100000001100111111ULL));

}

TEST_CASE("split block with appended garbage (n=32, middle=16)", "[split_block]") {
    block x = block(1290545303681682445ULL, 0b011011011011000101010100011110001101111010ULL);
    size_t n = 32;
    size_t middle = 16;

    std::array<block,2> blocks;
    split_block(x, n, middle, blocks);

    REQUIRE(blocks[0] == block(0, 0b1110001101111010ULL));
    REQUIRE(blocks[1] == block(0, 0b1100010101010001ULL));

}

TEST_CASE("split block with appended garbage (n=32, middle=3)", "[split_block]") {
    block x = block(1290545303681682445ULL, 0b011011011011000101010100011110001101111010ULL);
    size_t n = 32;
    size_t middle = 3;

    std::array<block,2> blocks;
    split_block(x, n, middle, blocks);

    REQUIRE(blocks[0] == block(0, 0b010ULL));
    REQUIRE(blocks[1] == block(0, 0b11000101010100011110001101111ULL));

}

TEST_CASE("split block with appended garbage (n=32, middle=25)", "[split_block]") {
    block x = block(1290545303681682445ULL, 0b011011011011000101010100011110001101111010ULL);
    size_t n = 32;
    size_t middle = 25;

    std::array<block,2> blocks;
    split_block(x, n, middle, blocks);

    REQUIRE(blocks[0] == block(0, 0b1010100011110001101111010ULL));
    REQUIRE(blocks[1] == block(0, 0b1100010ULL));

}