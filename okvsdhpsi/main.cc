
#include <sys/types.h>

#include <cstddef>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <memory>
#include <vector>

#include "examples/okvsdhpsi/malicious/okvsdhpsi.h"
#include "examples/okvsdhpsi/okvs/baxos.h"
#include "examples/okvsdhpsi/semihonest/okvsdhpsi.h"

#include "yacl/base/int128.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/link/link.h"
#include "yacl/link/test_util.h"

std::vector<uint128_t> CreateRangeItems(size_t begin, size_t size) {
  std::vector<uint128_t> ret;
  for (size_t i = 0; i < size; ++i) {
    ret.push_back(yacl::crypto::Blake3_128(std::to_string(begin + i)));
  }
  return ret;
}

void TestSemiHonest() {
  const uint64_t level = 10;
  const uint64_t num = 1 << level;
  size_t bin_size = num;
  size_t weight = 3;
  // statistical security parameter
  size_t ssp = 40;
  size_t mask_length = ((40 + 2 * level) + 7) / 8;
  okvs::Baxos baxos;
  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());

  uint128_t seed;
  prng.Fill(absl::MakeSpan(&seed, 1));

  SPDLOG_INFO("items_num:{}, bin_size:{}", num, bin_size);

  baxos.Init(num, bin_size, weight, ssp, okvs::PaxosParam::DenseType::GF128,
             seed);

  SPDLOG_INFO("baxos.size(): {}", baxos.size());

  std::vector<uint128_t> items_a = CreateRangeItems(0, num);
  std::vector<uint128_t> items_b = CreateRangeItems(10, num);

  auto lctxs = yacl::link::test::SetupWorld(2);  // setup network

  auto start_time = std::chrono::high_resolution_clock::now();

  std::future<void> sender = std::async(std::launch::async, [&] {
    semihonest::OkvsDHPsiSend(lctxs[0], items_a, baxos, mask_length);
  });

  std::future<std::vector<int32_t>> receiver =
      std::async(std::launch::async, [&] {
        return semihonest::OkvsDHPsiRecv(lctxs[1], items_b, baxos, mask_length);
      });
  sender.get();
  auto psi_result = receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::cout << psi_result.size() << std::endl;
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  ;

  std::sort(psi_result.begin(), psi_result.end());
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = lctxs[0]->GetStats();
  auto receiver_stats = lctxs[1]->GetStats();
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

void TestMalicious() {
  const uint64_t level = 10;
  const uint64_t num = 1 << level;
  size_t bin_size = num;
  size_t weight = 3;
  // statistical security parameter
  size_t ssp = 40;
  okvs::Baxos baxos;
  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());

  uint128_t seed;
  prng.Fill(absl::MakeSpan(&seed, 1));

  SPDLOG_INFO("items_num:{}, bin_size:{}", num, bin_size);

  baxos.Init(num, bin_size, weight, ssp, okvs::PaxosParam::DenseType::GF128,
             seed);

  SPDLOG_INFO("baxos.size(): {}", baxos.size());

  std::vector<uint128_t> items_a = CreateRangeItems(0, num);
  std::vector<uint128_t> items_b = CreateRangeItems(10, num);

  auto lctxs = yacl::link::test::SetupWorld(2);  // setup network

  auto start_time = std::chrono::high_resolution_clock::now();

  std::future<void> sender = std::async(std::launch::async, [&] {
    malicious::OkvsDHPsiSend(lctxs[0], items_a, baxos);
  });

  std::future<std::vector<int32_t>> receiver = std::async(
      std::launch::async,
      [&] { return malicious::OkvsDHPsiRecv(lctxs[1], items_b, baxos); });
  sender.get();
  auto psi_result = receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::cout << psi_result.size() << std::endl;
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  ;

  std::sort(psi_result.begin(), psi_result.end());
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = lctxs[0]->GetStats();
  auto receiver_stats = lctxs[1]->GetStats();
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

int main() {
  TestSemiHonest();
  // TestMalicious();
}