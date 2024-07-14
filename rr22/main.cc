#include <iostream>
#include <vector>
#include "examples/okvs/galois128.h"
#include "yacl/utils/parallel.h"

#include "yacl/base/int128.h"
#include "yacl/kernel/algorithms/silent_vole.h"
#include "yacl/link/test_util.h"
#include "examples/okvs/baxos.h"

using namespace yacl::crypto;
using namespace std;

std::vector<uint128_t> CreateRangeItems(size_t begin, size_t size) {
  std::vector<uint128_t> ret;
  for (size_t i = 0; i < size; ++i) {
    ret.push_back(yacl::crypto::Blake3_128(std::to_string(begin + i)));
  }
  return ret;
}

std::vector<uint128_t> RR22PsiRecv(
    const std::shared_ptr<yacl::link::Context>& ctx,
    std::vector<uint128_t>& elem_hashes,
    okvs::Baxos baxos) {
  
  uint128_t okvssize = baxos.size();

  //VOLE
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(okvssize),
                 "baxos.size");
    //VOLE
  const auto codetype = yacl::crypto::CodeType::ExAcc11;
  std::vector<uint128_t> a(okvssize);
  std::vector<uint128_t> c(okvssize);
  auto volereceiver = std::async([&] {
    auto sv_receiver = yacl::crypto::SilentVoleReceiver(codetype);
    sv_receiver.Recv(ctx, absl::MakeSpan(a), absl::MakeSpan(c));
  });
  

  // Encode
  std::vector<uint128_t> p(okvssize);
  baxos.Solve(absl::MakeSpan(elem_hashes), absl::MakeSpan(elem_hashes), absl::MakeSpan(p),nullptr,8);
  
  std::vector<uint128_t> aprime(okvssize);

  yacl::parallel_for(0, aprime.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      aprime[idx] = a[idx] ^ p[idx];
    }
  });
  volereceiver.get();
  ctx->SendAsync(ctx->NextRank(),
                 yacl::ByteContainerView(aprime.data(),
                                         aprime.size() * sizeof(uint128_t)),
                 "Send A' = P+A");
  std::vector<uint128_t> receivermasks(elem_hashes.size());
  baxos.Decode(absl::MakeSpan(elem_hashes), absl::MakeSpan(receivermasks), absl::MakeSpan(c),8);
  std::vector<uint128_t> sendermasks(elem_hashes.size());
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive masks of sender");
  YACL_ENFORCE(buf.size() == int64_t(elem_hashes.size() * sizeof(uint128_t)));
  std::memcpy(sendermasks.data(), buf.data(), buf.size());
  
  // 确保输入向量是排序的
  std::sort(sendermasks.begin(), sendermasks.end());
  std::sort(receivermasks.begin(), receivermasks.end());

  std::vector<uint128_t> intersection;
  std::set_intersection(
      sendermasks.begin(), sendermasks.end(),
      receivermasks.begin(), receivermasks.end(),
      std::back_inserter(intersection)
  );
  cout<<intersection.size()<<endl;
  return {};
}

void RR22PsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
                 std::vector<uint128_t>& elem_hashes,
                 okvs::Baxos baxos) {
  size_t okvssize =
      DeserializeUint128(ctx->Recv(ctx->PrevRank(), "baxos.size"));
  const auto codetype = yacl::crypto::CodeType::ExAcc11;
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
  yacl::parallel_for(
      0, okvssize, [&](int64_t begin, int64_t end) {
        for (int64_t idx = begin; idx < end; ++idx) {
          k[idx] =
              b[idx] ^
              (delta_gf128 * aprime[idx]).get<uint128_t>(0);
        }
      });
  std::vector<uint128_t> sendermasks(elem_hashes.size());
  baxos.Decode(absl::MakeSpan(elem_hashes), absl::MakeSpan(sendermasks), absl::MakeSpan(k),8);
  yacl::parallel_for(
      0, elem_hashes.size(), [&](int64_t begin, int64_t end) {
        for (int64_t idx = begin; idx < end; ++idx) {
          sendermasks[idx] =
              sendermasks[idx] ^
              (delta_gf128 * elem_hashes[idx]).get<uint128_t>(0);
        }
      });
  ctx->SendAsync(ctx->NextRank(),
                 yacl::ByteContainerView(sendermasks.data(),
                                         sendermasks.size() * sizeof(uint128_t)),
                 "Send masks of sender");
}



int main() {
  // 确保链接上下文定义正确
    // 准备OKVS的参数
  const uint64_t num = 16777216;
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
  std::vector<uint128_t> items_b = CreateRangeItems(1, num);
  auto lctxs = yacl::link::test::SetupWorld(2);  // setup network

  std::future<void> rr22_sender = std::async(std::launch::async, [&] {
    RR22PsiSend(lctxs[0], items_a,baxos);
  });

  std::future<std::vector<uint128_t>> rr22_receiver = std::async(std::launch::async, [&] {
    return RR22PsiRecv(lctxs[1], items_b,baxos);
  });

  rr22_sender.get();
  auto psi_result = rr22_receiver.get();
  std::sort(psi_result.begin(), psi_result.end());
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = lctxs[0]->GetStats();
  auto receiver_stats = lctxs[1]->GetStats();
  std::cout << "Sender sent bytes: " << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Sender received bytes: " << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver sent bytes: " << bytesToMB(receiver_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver received bytes: " << bytesToMB(receiver_stats->recv_bytes.load()) << " MB" << std::endl;
}
