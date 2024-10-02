#include <iostream>
#include <vector>

#include "examples/okvs/galois128.h"

#include "yacl/kernel/algorithms/silent_vole.h"
#include "yacl/link/test_util.h"

using namespace yacl::crypto;

int main() {
  // 确保链接上下文定义正确
  auto lctxs = yacl::link::test::SetupWorld(2);  // setup network

  const auto codetype = yacl::crypto::CodeType::ExAcc11;
  const uint64_t num = 1048576;

  std::vector<uint128_t> a(num);
  std::vector<uint128_t> b(num);
  std::vector<uint128_t> c(num);
  uint128_t delta = 0;

  auto start_time = std::chrono::high_resolution_clock::now();
  auto sender = std::async([&] {
    auto sv_sender = yacl::crypto::SilentVoleSender(codetype);
    sv_sender.Send(lctxs[0], absl::MakeSpan(b));
    delta = sv_sender.GetDelta();
  });

  auto receiver = std::async([&] {
    auto sv_receiver = yacl::crypto::SilentVoleReceiver(codetype);
    sv_receiver.Recv(lctxs[1], absl::MakeSpan(a), absl::MakeSpan(c));
  });

  sender.get();
  receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Send and Receive operations took " << duration.count()
            << " seconds." << std::endl;

  okvs::Galois128 delta_gf128(delta);
  auto sender_stats = lctxs[0]->GetStats();
  auto receiver_stats = lctxs[1]->GetStats();

  std::cout << "Sender sent bytes: " << sender_stats->sent_bytes.load()
            << std::endl;
  std::cout << "Sender received bytes: " << sender_stats->recv_bytes.load()
            << std::endl;
  std::cout << "Receiver sent bytes: " << receiver_stats->sent_bytes.load()
            << std::endl;
  std::cout << "Receiver received bytes: " << receiver_stats->recv_bytes.load()
            << std::endl;

  SPDLOG_INFO("delta:{}", delta);
  SPDLOG_INFO("a[i]:{}, b[i]:{}, c[0]:{}", a[0], b[0], c[0]);
  SPDLOG_INFO("a[i]*delta ^ b[0]:{}",
              (delta_gf128 * a[0]).get<uint128_t>(0) ^ b[0]);
  for (uint64_t i = 0; i < num; ++i) {
    auto ci = (delta_gf128 * a[i]).get<uint128_t>(0) ^ b[i];
    std::cout << ci << std::endl;
    std::cout << c[i] << std::endl;
  }
}
