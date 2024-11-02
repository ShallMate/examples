
#include <cstddef>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <memory>
#include <vector>

#include "examples/okvsdhpsi/okvs/baxos.h"
#include "examples/okvsdhpsi/okvsdhpsi.h"

#include "yacl/base/int128.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/link/link.h"
#include "yacl/link/test_util.h"
#include "yacl/utils/parallel.h"

std::vector<uint128_t> CreateRangeItems(size_t begin, size_t size) {
  std::vector<uint128_t> ret;
  for (size_t i = 0; i < size; ++i) {
    ret.push_back(yacl::crypto::Blake3_128(std::to_string(begin + i)));
  }
  return ret;
}

int ExamplePSI() {
  auto ec = yacl::crypto::EcGroupFactory::Instance().Create(
      /* curve name */ "FourQ");
  size_t n = 1 << 10;
  size_t bin_size = n / 4;
  size_t weight = 3;
  // statistical security parameter
  size_t ssp = 40;

  okvs::Baxos baxos;
  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());

  uint128_t seed;
  prng.Fill(absl::MakeSpan(&seed, 1));

  SPDLOG_INFO("items_num:{}, bin_size:{}", n, bin_size);

  baxos.Init(n, bin_size, weight, ssp, okvs::PaxosParam::DenseType::GF128,
             seed);

  auto p = ec->GetOrder();
  auto as = yacl::crypto::RandVec<uint128_t>(n);
  auto bs = yacl::crypto::RandVec<uint128_t>(n);
  std::vector<yacl::math::MPInt> cs(n);
  std::vector<yacl::crypto::EcPoint> ps1(n);
  std::vector<yacl::crypto::EcPoint> ps2(n);
  std::vector<uint128_t> okvs(baxos.size());
  auto start_time = std::chrono::high_resolution_clock::now();
  baxos.Solve(absl::MakeSpan(as), absl::MakeSpan(bs), absl::MakeSpan(okvs),
              nullptr, 8);
  baxos.Decode(absl::MakeSpan(as), absl::MakeSpan(bs), absl::MakeSpan(okvs), 8);
  yacl::parallel_for(0, n, [&](int64_t beg, int64_t end) {
    for (int64_t i = beg; i < end; ++i) {
      yacl::math::MPInt::Mul(yacl::math::MPInt(as[i]), yacl::math::MPInt(bs[i]),
                             &cs[i]);
      cs[i] = cs[i].Mod(p);
      ps1[i] = ec->MulBase(cs[i]);
    }
  });
  yacl::parallel_for(0, n, [&](int64_t beg, int64_t end) {
    for (int64_t i = beg; i < end; ++i) {
      ps2[i] = ec->MulBase(yacl::math::MPInt(as[i]));
    }
  });
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  ;

  return 0;
}

int main() {
  const uint64_t num = 1 << 20;
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

  std::future<void> sender = std::async(
      std::launch::async, [&] { OkvsDHPsiSend(lctxs[0], items_a, baxos); });

  std::future<std::vector<int32_t>> receiver =
      std::async(std::launch::async,
                 [&] { return OkvsDHPsiRecv(lctxs[1], items_b, baxos); });
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