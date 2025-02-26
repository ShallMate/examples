#include <iostream>
#include <vector>

#include "examples/opprfpsu/okvs/baxos.h"
#include "examples/opprfpsu/okvs/galois128.h"
#include "examples/opprfpsu/opprf.h"
#include "examples/opprfpsu/opprfpsu.h"

#include "yacl/base/int128.h"
#include "yacl/kernel/algorithms/silent_vole.h"
#include "yacl/link/test_util.h"
#include "yacl/utils/parallel.h"

using namespace yacl::crypto;
using namespace std;

std::vector<uint128_t> CreateRangeItems(size_t begin, size_t size) {
  std::vector<uint128_t> ret;
  for (size_t i = 0; i < size; ++i) {
    ret.push_back(yacl::crypto::Blake3_128(std::to_string(begin + i)));
  }
  return ret;
}

int RunOPPRF() {
  const uint64_t ns = 1.3 * (1 << 20);
  const uint64_t nr = 3 * (1 << 20);
  size_t sender_bin_size = ns;
  size_t recv_bin_size = nr;
  size_t weight = 3;
  // statistical security parameter
  size_t ssp = 40;

  okvs::Baxos sendbaxos;
  okvs::Baxos recvbaxos;
  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());

  uint128_t seed;
  prng.Fill(absl::MakeSpan(&seed, 1));
  sendbaxos.Init(ns, sender_bin_size, weight, ssp,
                 okvs::PaxosParam::DenseType::GF128, seed);
  recvbaxos.Init(nr, recv_bin_size, weight, ssp,
                 okvs::PaxosParam::DenseType::GF128, seed);

  std::vector<uint128_t> items_a = CreateRangeItems(0, ns);
  std::vector<uint128_t> items_b = CreateRangeItems(0, ns);
  std::vector<uint128_t> items_c = CreateRangeItems(0, nr);

  auto lctxs = yacl::link::test::SetupBrpcWorld(2);  // setup network

  auto start_time = std::chrono::high_resolution_clock::now();

  std::future<void> opprf_sender = std::async(std::launch::async, [&] {
    opprf::OPPRFSend(lctxs[0], items_a, items_b, sendbaxos, recvbaxos);
  });

  std::future<std::vector<uint128_t>> opprf_receiver =
      std::async(std::launch::async, [&] {
        return opprf::OPPRFRecv(lctxs[1], items_c, sendbaxos, recvbaxos);
      });

  opprf_sender.get();
  auto prf_result = opprf_receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  if (std::equal(prf_result.begin(), prf_result.end(), items_b.begin())) {
    std::cout << "items_b and prf_result are equal." << std::endl;
  } else {
    std::cout << "items_b and prf_result are not equal." << std::endl;
  }

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
  return 0;
}

int RunPSU() {
  const uint64_t ns = 1 << 21;
  const uint64_t nr = 1 << 21;

  okvs::Baxos sendbaxos;
  okvs::Baxos recvbaxos;
  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());

  uint128_t seed;
  prng.Fill(absl::MakeSpan(&seed, 1));

  std::vector<uint128_t> items_a = CreateRangeItems(0, ns);
  std::vector<uint128_t> items_c = CreateRangeItems(0, nr);

  auto lctxs = yacl::link::test::SetupBrpcWorld(2);  // setup network

  auto start_time = std::chrono::high_resolution_clock::now();

  std::future<void> opprfpsu_sender = std::async(
      std::launch::async, [&] { OPPRFPSUSend(lctxs[0], items_a, seed); });

  std::future<std::vector<uint128_t>> opprfpsu_receiver =
      std::async(std::launch::async,
                 [&] { return OPPRFPSURecv(lctxs[1], items_c, seed); });

  opprfpsu_sender.get();
  auto psu_result = opprfpsu_receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
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
  return 0;
}

int main() { RunPSU(); }