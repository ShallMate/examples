#include <functional>
#include "examples/bokvs/bokvs.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/utils/parallel.h"
#include "examples/okvs/galois128.h"
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
    size_t n = 1<<20;
    size_t w = 512;
    double e = 1.01;

    // 创建OKVSBK实例
    OKVSBK ourokvs(n, w, e);
    auto r = ourokvs.getR();
    // 打印类的成员变量值
    std::cout << "N: " << ourokvs.getN() << std::endl;
    std::cout << "M: " << ourokvs.getM() << std::endl;
    std::cout << "W: " << ourokvs.getW() << std::endl;
    std::cout << "R: " << r << std::endl;
    std::cout << "e: " << ourokvs.getE() << std::endl;
    std::vector<uint128_t> keys = CreateRangeItems(0, n);
    std::vector<uint128_t> values = CreateRangeItems(10, n);
    auto start = std::chrono::high_resolution_clock::now();

    // 执行Encode函数
    ourokvs.Encode(keys, values);

    // 结束计时
    auto end = std::chrono::high_resolution_clock::now();

    // 计算运行时间（毫秒）
    std::chrono::duration<double, std::milli> duration = end - start;
    // 输出运行时间
    std::cout << "Encode函数运行时间: " << duration.count() << " 毫秒" << std::endl;
    std::vector<uint128_t> values1(n,0);
    ourokvs.Decode(keys, values1);
    if (std::equal(values.begin(), values.end(), values1.begin())) {
        std::cout << "Values 和 Values1 相等" << std::endl;
    } else {
        std::cout << "Values 和 Values1 不相等" << std::endl;
    }
    uint128_t delta = 100;
    okvs::Galois128 delta_gf128(delta);
    ourokvs.Mul(delta_gf128);
    std::vector<uint128_t> values2(n,0);
    ourokvs.Decode(keys, values2);
    yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
          values[idx] = (delta_gf128 * values[idx]).get<uint128_t>(0);   
        }
    });
    if (std::equal(values.begin(), values.end(), values2.begin())) {
        std::cout << "Values 和 Values2 相等" << std::endl;
    } else {
        std::cout << "Values 和 Values2 不相等" << std::endl;
    }
}