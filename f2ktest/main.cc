#include <iostream>
#include <bitset>
#include "yacl/base/int128.h"
#include "yacl/math/f2k/f2k.h"



uint128_t binaryStringToUint128(const std::string& binary) {
    uint64_t high = std::bitset<64>(binary.substr(0, 64)).to_ullong();
    uint64_t low = std::bitset<64>(binary.substr(64, 64)).to_ullong();
    return yacl::MakeUint128(high, low);
}

void printUint128(uint128_t value) {
    uint64_t high = absl::Uint128High64(value);
    uint64_t low = absl::Uint128Low64(value);
    std::cout << "0x" << std::hex << high << low << std::dec << std::endl;
}

int main() {
    // 输入128位二进制字符串
    std::string binaryString = "1100101011110110111010101101110101110010101101010111010101010010";
    
    // 将二进制字符串转换为uint128_t
    uint128_t element = binaryStringToUint128(binaryString);

    // 计算逆元
    uint128_t inverse = yacl::GfInv128(element);

    // 验证逆元
    uint128_t product = yacl::GfMul128(element, inverse);

    // 打印结果
    std::cout << "Element: ";
    printUint128(element);
    std::cout << "Inverse: ";
    printUint128(inverse);
    std::cout << "Product: ";
    printUint128(product);

    // 验证product是否等于1
    if (product == yacl::MakeUint128(0, 1)) {
        std::cout << "GfInv128 is correct." << std::endl;
    } else {
        std::cout << "GfInv128 is incorrect." << std::endl;
    }
    std::string binaryString1 = "1100101011110110100010101101010101110010101101010110010101010010";
    std::string binaryString2 = "1010101010101010101010101010101010101010101010101010101010101010";
    
    // 将二进制字符串转换为uint128_t
    uint128_t element1 = binaryStringToUint128(binaryString1);
    uint128_t element2 = binaryStringToUint128(binaryString2);

    // 计算加法
    uint128_t result = yacl::GfAdd128(element1, element2);

    // 打印结果
    std::cout << "Element 1: ";
    printUint128(element1);
    std::cout << "Element 2: ";
    printUint128(element2);
    std::cout << "Result: ";
    printUint128(result);

    uint128_t expectedResult = element1 ^ element2;
    if (result == expectedResult) {
        std::cout << "GfAdd128 is correct." << std::endl;
    } else {
        std::cout << "GfAdd128 is incorrect." << std::endl;
    }

    return 0;
}
