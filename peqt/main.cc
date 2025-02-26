
#include <vector>

#include "yacl/base/int128.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/crypto/tools/prg.h"
#include "yacl/link/context.h"
#include "yacl/link/test_util.h"
#include "yacl/math/f2k/f2k.h"
#include "yacl/utils/parallel.h"
#include "yacl/utils/serialize.h"

std::vector<uint128_t> CreateRangeItems(size_t begin, size_t size) {
  std::vector<uint128_t> ret;
  for (size_t i = 0; i < size; ++i) {
    ret.push_back(yacl::crypto::Blake3_128(std::to_string(begin + i)));
  }
  return ret;
}

std::vector<uint128_t> PEQTSend(const std::shared_ptr<yacl::link::Context>& ctx,
                                std::vector<uint128_t>& elem_hashes,
                                std::vector<uint128_t>& A,
                                std::vector<uint128_t>& C1) {
  std::vector<uint128_t> E(elem_hashes.size());

  yacl::parallel_for(0, elem_hashes.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      E[idx] = C1[idx] ^ yacl::crypto::Blake3_128(
                             yacl::SerializeUint128(elem_hashes[idx]));
    }
  });
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(E.data(), E.size() * sizeof(uint128_t)),
      "Send E");
  return A;
}

std::vector<uint128_t> PEQTRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                                std::vector<uint128_t>& elem_hashes,
                                std::vector<uint128_t>& B,
                                std::vector<uint128_t>& C2) {
  std::vector<uint128_t> E(elem_hashes.size());
  std::vector<uint128_t> A(elem_hashes.size());
  auto ebuf = ctx->Recv(ctx->PrevRank(), "Receive E");
  YACL_ENFORCE(ebuf.size() == int64_t(elem_hashes.size() * sizeof(uint128_t)));
  std::memcpy(E.data(), ebuf.data(), ebuf.size());

  yacl::parallel_for(0, elem_hashes.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      uint128_t inv = yacl::GfInv128(B[idx]);
      uint128_t res =
          E[idx] ^
          yacl::crypto::Blake3_128(yacl::SerializeUint128(elem_hashes[idx])) ^
          C2[idx];
      A[idx] = yacl::GfMul128(res, inv);
    }
  });
  return A;
}

int main() {
  size_t n = 1 << 20;
  uint128_t seed;
  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());
  prng.Fill(absl::MakeSpan(&seed, 1));
  // 创建一个 vector 来存储随机数
  std::vector<uint128_t> A(n);
  std::vector<uint128_t> B(n);
  std::vector<uint128_t> C1(n);
  std::vector<uint128_t> C2(n);
  prng.Fill(absl::MakeSpan(A));
  prng.Fill(absl::MakeSpan(B));
  prng.Fill(absl::MakeSpan(C1));
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      C2[idx] = yacl::GfMul128(A[idx], B[idx]) ^ C1[idx];
    }
  });
  std::vector<uint128_t> items_a = CreateRangeItems(0, n);
  std::vector<uint128_t> items_b = CreateRangeItems(0, n);
  auto lctxs = yacl::link::test::SetupWorld(2);  // setup network
  auto start_time = std::chrono::high_resolution_clock::now();
  // sender 任务：返回 std::vector<uint128_t>
  std::future<std::vector<uint128_t>> sender = std::async(
      std::launch::async, [&] { return PEQTSend(lctxs[0], items_a, A, C1); });

  // receiver 任务：返回 std::vector<uint128_t>
  std::future<std::vector<uint128_t>> receiver = std::async(
      std::launch::async, [&] { return PEQTRecv(lctxs[1], items_b, B, C2); });

  sender.get();
  receiver.get();
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
  return 1;
}