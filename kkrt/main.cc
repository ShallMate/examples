#include <iostream>
#include <vector>

#include "examples/kkrt/kkrt_psi.h"

#include "yacl/base/int128.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/link/test_util.h"

std::vector<uint128_t> CreateRangeItems(size_t begin, size_t size) {
  std::vector<uint128_t> ret(size);
  for (size_t i = 0; i < size; i++) {
    auto hash = yacl::crypto::Blake3(std::to_string(begin + i));
    memcpy(&ret[i], hash.data(), sizeof(uint128_t));
  }
  return ret;
}

int main() {
  size_t n = 1 << 24;
  auto alice_items = CreateRangeItems(1, n);
  auto bob_items = CreateRangeItems(2, n);
  auto contexts = yacl::link::test::SetupWorld(2);
  auto start_time = std::chrono::high_resolution_clock::now();
  std::future<void> kkrt_psi_sender =
      std::async([&] { return KkrtPsiSend(contexts[0], alice_items); });
  std::future<std::vector<std::size_t>> kkrt_psi_receiver =
      std::async([&] { return KkrtPsiRecv(contexts[1], bob_items); });

  kkrt_psi_sender.get();
  auto results_b = kkrt_psi_receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();

  // 计算运行时间
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "KKRT Time: " << duration.count() << " 秒" << std::endl;
  std::cout << results_b.size() << std::endl;
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = contexts[0]->GetStats();
  auto receiver_stats = contexts[1]->GetStats();
  std::cout << "Sender sent bytes: "
            << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Sender received bytes: "
            << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver sent bytes: "
            << bytesToMB(receiver_stats->sent_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Receiver received bytes: "
            << bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Total Communication: "
            << bytesToMB(receiver_stats->sent_bytes.load()) +
                   bytesToMB(receiver_stats->recv_bytes.load())
            << " MB" << std::endl;
}
