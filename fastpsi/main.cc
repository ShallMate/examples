#include <iostream>
#include <ostream>
#include <vector>

#include "examples/fastpsi/bokvs.h"
#include "examples/okvs/galois128.h"

#include "yacl/base/int128.h"
#include "yacl/kernel/algorithms/silent_vole.h"
#include "yacl/link/test_util.h"
#include "yacl/utils/parallel.h"

using namespace yacl::crypto;
using namespace std;

struct Uint128Hash {
    size_t operator()(const uint128_t& key) const {
        return std::hash<uint64_t>()(static_cast<uint64_t>(key)) ^ std::hash<uint64_t>()(static_cast<uint64_t>(key >> 64));
    }
};

std::vector<uint128_t> CreateRangeItems(size_t begin, size_t size) {
  std::vector<uint128_t> ret;
  for (size_t i = 0; i < size; ++i) {
    ret.push_back(yacl::crypto::Blake3_128(std::to_string(begin + i)));
  }
  return ret;
}

std::vector<uint128_t> FastPsiRecv(
    const std::shared_ptr<yacl::link::Context>& ctx,
    std::vector<uint128_t>& elem_hashes, OKVSBK ourokvs) {
  uint128_t okvssize = ourokvs.getM();


  // VOLE
  const auto codetype = yacl::crypto::CodeType::Silver5;
  std::vector<uint128_t> a(okvssize);
  std::vector<uint128_t> c(okvssize);
  auto volereceiver = std::async([&] {
    auto sv_receiver = yacl::crypto::SilentVoleReceiver(codetype);
    sv_receiver.Recv(ctx, absl::MakeSpan(a), absl::MakeSpan(c));
  });

  // Encode
  ourokvs.Encode(elem_hashes, elem_hashes);
  std::vector<uint128_t> aprime(okvssize);

  yacl::parallel_for(0, aprime.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      aprime[idx] = a[idx] ^ ourokvs.p_[idx];
    }
  });
  volereceiver.get();
  
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(aprime.data(), aprime.size() * sizeof(uint128_t)),
      "Send A' = P+A");
  std::vector<uint128_t> receivermasks(elem_hashes.size());
  ourokvs.DecodeOtherP(elem_hashes, receivermasks,c);
  std::vector<uint128_t> sendermasks(elem_hashes.size());
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive masks of sender");
  YACL_ENFORCE(buf.size() == int64_t(elem_hashes.size() * sizeof(uint128_t)));
  std::memcpy(sendermasks.data(), buf.data(), buf.size());

  unordered_set<uint128_t, Uint128Hash> sender_set(sendermasks.begin(), sendermasks.end());
  std::vector<uint128_t> intersection_elements;
  std::mutex intersection_mutex;

  // 使用 yacl::parallel_for 查找交集并加入结果
  yacl::parallel_for(0, receivermasks.size(), [&](int64_t begin, int64_t end) {
      for (int64_t idx = begin; idx < end; ++idx) {
          if (sender_set.find(receivermasks[idx]) != sender_set.end()) {
              std::lock_guard<std::mutex> lock(intersection_mutex);
              intersection_elements.push_back(elem_hashes[idx]);
          }
      }
  });
  return intersection_elements;
}

void FastPsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
                 std::vector<uint128_t>& elem_hashes, OKVSBK ourokvs) {
  uint128_t okvssize = ourokvs.getM();
  const auto codetype = yacl::crypto::CodeType::Silver5;
  std::vector<uint128_t> b(okvssize);
  uint128_t delta = 0;
  auto volesender = std::async([&] {
    auto sv_sender = yacl::crypto::SilentVoleSender(codetype);
    sv_sender.Send(ctx, absl::MakeSpan(b));
    delta = sv_sender.GetDelta();
  });
  volesender.get();
  std::vector<uint128_t> aprime(okvssize);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive A' = P+A");
  YACL_ENFORCE(buf.size() == int64_t(okvssize * sizeof(uint128_t)));
  std::memcpy(aprime.data(), buf.data(), buf.size());
  okvs::Galois128 delta_gf128(delta);
  std::vector<uint128_t> k(okvssize);
  yacl::parallel_for(0, okvssize, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      k[idx] = b[idx] ^ (delta_gf128 * aprime[idx]).get<uint128_t>(0);
    }
  });
  std::vector<uint128_t> sendermasks(elem_hashes.size());
  ourokvs.DecodeOtherP(elem_hashes, sendermasks,k);
  yacl::parallel_for(0, elem_hashes.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sendermasks[idx] =
          sendermasks[idx] ^ (delta_gf128 * elem_hashes[idx]).get<uint128_t>(0);
    }
  });
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(sendermasks.data(),
                              sendermasks.size() * sizeof(uint128_t)),
      "Send masks of sender");
}

int main() {
  size_t n = 1<<20;
  size_t w = 512;
  double e = 1.01;
  OKVSBK ourokvs(n, w, e);
  auto r = ourokvs.getR();
  std::cout << "N: " << ourokvs.getN() << std::endl;
  std::cout << "M: " << ourokvs.getM() << std::endl;
  std::cout << "W: " << ourokvs.getW() << std::endl;
  std::cout << "R: " << r << std::endl;
  std::cout << "e: " << ourokvs.getE() << std::endl;

  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());

  uint128_t seed;
  prng.Fill(absl::MakeSpan(&seed, 1));
  std::vector<uint128_t> items_a = CreateRangeItems(0, n);
  std::vector<uint128_t> items_b = CreateRangeItems(10, n);
  
  auto lctxs = yacl::link::test::SetupWorld(2);  // setup network


  auto start_time = std::chrono::high_resolution_clock::now();

  std::future<void> fastpsi_sender = std::async(
      std::launch::async, [&] { FastPsiSend(lctxs[0], items_a, ourokvs); });

  std::future<std::vector<uint128_t>> fastpsi_receiver =
      std::async(std::launch::async,
                 [&] { return FastPsiRecv(lctxs[1], items_b, ourokvs); });

  fastpsi_sender.get();
  auto psi_result = fastpsi_receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  ;

  std::sort(psi_result.begin(), psi_result.end());
  //std::cout<<psi_result.size()<<std::endl;
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
}
