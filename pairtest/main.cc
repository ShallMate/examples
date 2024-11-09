#include <chrono>
#include <iostream>

#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/pairing/factory/pairing_spi.h"

int main() {
  std::string library_name = "bls12-381";
  auto pairing_group =
      yacl::crypto::PairingGroupFactory::Instance().Create(library_name);

  if (pairing_group) {
    // 记录 G1 和 G2 的生成元初始化时间
    auto start = std::chrono::high_resolution_clock::now();
    auto g1 = pairing_group->GetGroup1()->GetGenerator();
    auto g2 = pairing_group->GetGroup2()->GetGenerator();
    auto end = std::chrono::high_resolution_clock::now();
    std::cout << "生成元 G1 和 G2 初始化时间: "
              << std::chrono::duration_cast<std::chrono::microseconds>(end -
                                                                       start)
                     .count()
              << " 微秒" << std::endl;

    // 测试双线性对 Pairing 计算时间
    start = std::chrono::high_resolution_clock::now();
    auto gt_elem = pairing_group->Pairing(g1, g2);
    end = std::chrono::high_resolution_clock::now();
    std::cout << "双线性对 Pairing 计算时间: "
              << std::chrono::duration_cast<std::chrono::microseconds>(end -
                                                                       start)
                     .count()
              << " 微秒" << std::endl;

    // 测试标量乘法 MulBase
    yacl::crypto::MPInt scalar1("3");
    start = std::chrono::high_resolution_clock::now();
    auto p1 = pairing_group->GetGroup1()->MulBase(scalar1);
    end = std::chrono::high_resolution_clock::now();
    std::cout << "标量乘法 MulBase(3) 时间: "
              << std::chrono::duration_cast<std::chrono::microseconds>(end -
                                                                       start)
                     .count()
              << " 微秒" << std::endl;

    // 测试点加法 Add
    yacl::crypto::MPInt scalar2("5");
    auto p2 = pairing_group->GetGroup1()->MulBase(scalar2);
    start = std::chrono::high_resolution_clock::now();
    auto p1_plus_p2 = pairing_group->GetGroup1()->Add(p1, p2);
    end = std::chrono::high_resolution_clock::now();
    std::cout << "点加法 Add(P1, P2) 时间: "
              << std::chrono::duration_cast<std::chrono::microseconds>(end -
                                                                       start)
                     .count()
              << " 微秒" << std::endl;

    // 测试双线性对验证 e(P1 + P2, Q) = e(P1, Q) * e(P2, Q) 所需时间
    yacl::crypto::MPInt scalar3("7");
    auto q = pairing_group->GetGroup2()->MulBase(scalar3);

    start = std::chrono::high_resolution_clock::now();
    auto left = pairing_group->Pairing(p1_plus_p2, q);
    end = std::chrono::high_resolution_clock::now();
    std::cout << "双线性对 Pairing(P1 + P2, Q) 计算时间: "
              << std::chrono::duration_cast<std::chrono::microseconds>(end -
                                                                       start)
                     .count()
              << " 微秒" << std::endl;

    start = std::chrono::high_resolution_clock::now();
    auto right = pairing_group->GetGroupT()->Mul(pairing_group->Pairing(p1, q),
                                                 pairing_group->Pairing(p2, q));
    end = std::chrono::high_resolution_clock::now();
    std::cout << "群元素乘法 Mul(e(P1, Q), e(P2, Q)) 时间: "
              << std::chrono::duration_cast<std::chrono::microseconds>(end -
                                                                       start)
                     .count()
              << " 微秒" << std::endl;

    if (pairing_group->GetGroupT()->Equal(left, right)) {
      std::cout << "双线性对特性验证成功！" << std::endl;
    } else {
      std::cout << "双线性对特性验证失败！" << std::endl;
    }
  } else {
    std::cerr << "未能创建 pairing_group 实例。" << std::endl;
  }
  return 0;
}
