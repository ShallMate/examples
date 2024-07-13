#include <iostream>
#include <vector>
#include "examples/okvs/galois128.h"

#include "yacl/kernel/algorithms/silent_vole.h"
#include "yacl/link/test_util.h"

using namespace yacl::crypto;

int main() {
  // 确保链接上下文定义正确
  auto lctxs = yacl::link::test::SetupWorld(2);  // setup network

  const auto codetype = yacl::crypto::CodeType::Silver5;
  const uint64_t num = 10000;

  std::vector<uint128_t> a(num);
  std::vector<uint128_t> b(num);
  std::vector<uint128_t> c(num);
  uint128_t delta = 0;

  auto sender = std::async([&] {
    auto sv_sender = yacl::crypto::SilentVoleSender(codetype);
    sv_sender.Send(lctxs[0], absl::MakeSpan(c));
    delta = sv_sender.GetDelta();
  });

  auto receiver = std::async([&] {
    auto sv_receiver = yacl::crypto::SilentVoleReceiver(codetype);
    sv_receiver.Recv(lctxs[1], absl::MakeSpan(a), absl::MakeSpan(b));
  });

  sender.get();
  receiver.get();

  okvs::Galois128 delta_gf128(delta);

  SPDLOG_INFO("delta:{}", delta);
  SPDLOG_INFO("a[i]:{}, b[i]:{}, c[0]:{}", a[0], b[0], c[0]);
  SPDLOG_INFO("a[i]*delta ^ b[0]:{}",
              (delta_gf128 * a[0]).get<uint128_t>(0) ^ b[0]);

  for (uint64_t i = 0; i < num; ++i) {
    auto expected_value = (delta_gf128 * a[i]).get<uint128_t>(0) ^ b[i];
    std::cout<<expected_value<<std::endl;
    std::cout<<c[i]<<std::endl;
  }
}
