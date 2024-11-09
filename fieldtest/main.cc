#include <chrono>
#include <iostream>

#include "yacl/math/galois_field/gf.h"
#include "yacl/math/mpint/mp_int.h"

int main() {
  // 定义 secp256k1 的阶作为模数
  yacl::math::MPInt mod(2);

  // 创建 GF(n) 实例
  auto gf = yacl::math::GaloisFieldFactory::Instance().Create(
      yacl::math::kBinaryField,  // 域名称，表示素数域 GF(p)
      // yacl::math::ArgMod = mod,      // 模数 p，这里是 secp256k1 的阶 n
      yacl::math::ArgDegree = 64  // 扩展度 k，对于 GF(p) 为 1
      // 可根据需要添加其他参数，如 ArgMaxBitSize
  );
  std::cout << gf->GetLibraryName() << std::endl;

  if (!gf) {
    std::cerr << "Failed to create Galois Field instance." << std::endl;
    return -1;
  }

  // 随机生成两个域元素 a 和 b
  yacl::Item a = gf->Random();
  yacl::Item b = gf->Random();

  const int iterations = 10000;  // 执行次数

  // 测量加法性能
  {
    yacl::Item result = gf->Add(a, b);  // 初始化 result
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
      result = gf->Add(a, b);
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration =
        std::chrono::duration_cast<std::chrono::nanoseconds>(end - start)
            .count();
    double avg_time = duration / static_cast<double>(iterations);
    std::cout << "Average time for addition: " << avg_time << " ns"
              << std::endl;
  }

  // 测量减法性能
  {
    yacl::Item result = gf->Sub(a, b);  // 初始化 result
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
      result = gf->Sub(a, b);
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration =
        std::chrono::duration_cast<std::chrono::nanoseconds>(end - start)
            .count();
    double avg_time = duration / static_cast<double>(iterations);
    std::cout << "Average time for subtraction: " << avg_time << " ns"
              << std::endl;
  }

  // 测量乘法性能
  {
    yacl::Item result = gf->Mul(a, b);  // 初始化 result
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
      result = gf->Mul(a, b);
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration =
        std::chrono::duration_cast<std::chrono::nanoseconds>(end - start)
            .count();
    double avg_time = duration / static_cast<double>(iterations);
    std::cout << "Average time for multiplication: " << avg_time << " ns"
              << std::endl;
  }

  // 测量除法性能
  {
    yacl::Item result = gf->Div(a, b);  // 初始化 result
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
      result = gf->Div(a, b);
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration =
        std::chrono::duration_cast<std::chrono::nanoseconds>(end - start)
            .count();
    double avg_time = duration / static_cast<double>(iterations);
    std::cout << "Average time for division: " << avg_time << " ns"
              << std::endl;
  }

  // 测量求逆性能
  {
    yacl::Item result = gf->Inv(a);  // 初始化 result
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
      result = gf->Inv(a);
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration =
        std::chrono::duration_cast<std::chrono::nanoseconds>(end - start)
            .count();
    double avg_time = duration / static_cast<double>(iterations);
    std::cout << "Average time for inversion: " << avg_time << " ns"
              << std::endl;
    // yacl::math::MPInt num(result);
  }

  return 0;
}
