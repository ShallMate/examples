#include <functional>
#include "examples/bokvs/bokvs.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/utils/parallel.h"
#include <chrono>

using namespace std;

std::vector<uint128_t> CreateRangeItems(size_t begin, size_t size) {
  std::vector<uint128_t> ret;
  for (size_t i = 0; i < size; ++i) {
    ret.push_back(yacl::crypto::Blake3_128(std::to_string(begin + i)));
  }
  return ret;
}


int main() {
    // 示例参数
    size_t n = 1048576;
    size_t w = 256;
    double e = 1.03;

    // 创建OKVSBK实例
    OKVSBK okvs(n, w, e);
    auto r = okvs.getR();
    // 打印类的成员变量值
    std::cout << "N: " << okvs.getN() << std::endl;
    std::cout << "M: " << okvs.getM() << std::endl;
    std::cout << "W: " << okvs.getW() << std::endl;
    std::cout << "R: " << r << std::endl;
    std::cout << "e: " << okvs.getE() << std::endl;
    std::vector<uint128_t> keys = CreateRangeItems(0, n);
    std::vector<uint128_t> values = CreateRangeItems(10, n);
    auto p = okvs.Encode(keys, values);
  
}