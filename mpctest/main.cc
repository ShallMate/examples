#include "examples/mpctest/mpc19_psu.h"

#include <algorithm>
#include <future>
#include <iostream>
#include <set>
#include <string>
#include <vector>

#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/link/test_util.h"

std::vector<uint128_t> CreateRangeItems(size_t begin, size_t size) {
  std::vector<uint128_t> ret;
  for (size_t i = 0; i < size; ++i) {
    ret.push_back(yacl::crypto::Blake3_128(std::to_string(begin + i)));
  }
  return ret;
}

int main() {
  const int kWorldSize = 2;
  auto contexts = yacl::link::test::SetupWorld(kWorldSize);
  std::vector<uint128_t> items_a = CreateRangeItems(0, 1024);
  std::vector<uint128_t> items_b = CreateRangeItems(1, 1024);

  std::future<void> krtwpsu_sender = std::async(std::launch::async, [&] {
    KrtwPsuSend(contexts[0], items_a);
  });

  std::future<std::vector<uint128_t>> krtwpsu_receiver = std::async(std::launch::async, [&] {
    return KrtwPsuRecv(contexts[1], items_b);
  });

  krtwpsu_sender.get();
  auto psu_result = krtwpsu_receiver.get();
  std::sort(psu_result.begin(), psu_result.end());

  std::set<uint128_t> union_set;
  union_set.insert(items_a.begin(),items_a.end());
  union_set.insert(items_b.begin(), items_b.end());
  std::vector<uint128_t> union_vec(union_set.begin(), union_set.end());

  if (psu_result == union_vec) {
    std::cout << "Test passed!" << std::endl;
  } else {
    std::cout << "Test failed!" << std::endl;
    std::cout << "Expected: ";
    for (const auto& elem : union_vec) {
      std::cout << elem << " ";
    }
    std::cout << std::endl;
    std::cout << "Got: ";
    for (const auto& elem : psu_result) {
      std::cout << elem << " ";
    }
    std::cout << std::endl;
  }
  auto sender_stats = contexts[0]->GetStats();
  auto receiver_stats = contexts[1]->GetStats();

  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };

  std::cout << "Sender sent bytes: " << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Sender received bytes: " << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver sent bytes: " << bytesToMB(receiver_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver received bytes: " << bytesToMB(receiver_stats->recv_bytes.load()) << " MB" << std::endl;
  return 0;
}
