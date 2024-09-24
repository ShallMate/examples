#include <functional>
#include "examples/bokvspoint/bokvs.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/utils/parallel.h"
#include "examples/okvs/galois128.h"
#include <chrono>

using namespace std;
using yacl::crypto::EcGroupFactory;

std::vector<uint128_t> CreateRangeItems(size_t begin, size_t size) {
  std::vector<uint128_t> ret;
  for (size_t i = 0; i < size; ++i) {
    ret.push_back(yacl::crypto::Blake3_128(std::to_string(begin + i)));
  }
  return ret;
}

std::vector<uint32_t> CreateRangeItemsUint32(size_t size) {
  std::vector<uint32_t> ret;
  for (size_t i = 0; i < size; ++i) {
    ret.push_back(i);
  }
  return ret;
}


int main() {
    // 示例参数
    size_t n = 1<<20;
    size_t w = 256;
    double e = 1.05;
    // 创建OKVSBK实例
    OKVSBK ourokvs(n, w, e);
    auto r = ourokvs.getR();
    // 打印类的成员变量值
    std::cout << "N: " << ourokvs.getN() << std::endl;
    std::cout << "M: " << ourokvs.getM() << std::endl;
    std::cout << "W: " << ourokvs.getW() << std::endl;
    std::cout << "R: " << r << std::endl;
    std::cout << "e: " << ourokvs.getE() << std::endl;

    
    auto ec_group =
      EcGroupFactory::Instance().Create("secp256k1", yacl::ArgLib = "openssl");
    if (!ec_group) {
        std::cerr << "Failed to create secp256k1 curve using OpenSSL" << std::endl;
        return 1;
    }
    std::vector<yacl::math::MPInt> keys(n);
    yacl::parallel_for(1, n + 1, [&](int64_t beg, int64_t end) {
      for (int64_t i = beg; i < end; ++i) {
        yacl::math::MPInt value(i);
        auto point = ec_group->MulBase(value);
        auto affine_point = ec_group->GetAffinePoint(point);
        auto key = affine_point.x;
        keys[i] = key;
      }
    });
    cout<<"point prepare finish"<<endl;
    std::vector<uint32_t> values = CreateRangeItemsUint32(n);
    auto start = std::chrono::high_resolution_clock::now();

    // 执行Encode函数
    ourokvs.Encode(keys, values);

    // 结束计时
    auto end = std::chrono::high_resolution_clock::now();

    // 计算运行时间（毫秒）
    std::chrono::duration<double, std::milli> duration = end - start;
    // 输出运行时间
    std::cout << "Encode函数运行时间: " << duration.count() << " 毫秒" << std::endl;
    std::vector<uint32_t> values1(n,0);
    start = std::chrono::high_resolution_clock::now();
    ourokvs.DecodeSingle(keys, values1);
    // 结束计时
    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "Decode函数运行时间: " << duration.count() << " 毫秒" << std::endl;
    if (std::equal(values.begin(), values.end(), values1.begin())) {
        std::cout << "Values 和 Values1 相等" << std::endl;
    } else {
        std::cout << "Values 和 Values1 不相等" << std::endl;
    }
}