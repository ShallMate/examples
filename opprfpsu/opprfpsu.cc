// Copyright 2024 Guowei LING.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <iostream>
#include <vector>

#include "examples/opprfpsu/cuckoohash.h"
#include "examples/opprfpsu/okvs/galois128.h"
#include "examples/opprfpsu/opprf.h"

#include "yacl/base/int128.h"
#include "yacl/kernel/algorithms/silent_vole.h"
#include "yacl/utils/parallel.h"

void duplicate_elements(const std::vector<uint128_t>& elem_hashes,
                        std::vector<uint128_t>& values1,
                        std::vector<uint128_t>& values2,
                        std::vector<uint128_t>& values3,
                        std::vector<uint128_t>& ss, size_t cuckoolen) {
  yacl::parallel_for(0, elem_hashes.size(), [&](size_t begin, size_t end) {
    for (size_t i = begin; i < end; ++i) {
      values1[i] = ss[GetHash(1, elem_hashes[i]) % cuckoolen];
      values2[i] = ss[GetHash(2, elem_hashes[i]) % cuckoolen];
      values3[i] = ss[GetHash(3, elem_hashes[i]) % cuckoolen];
    }
  });
}

std::vector<uint128_t> OPPRFPSURecv(
    const std::shared_ptr<yacl::link::Context>& ctx,
    std::vector<uint128_t>& elem_hashes, uint128_t seed) {
  size_t cuckoolen =
      DeserializeUint128(ctx->Recv(ctx->PrevRank(), "the size of cuckoohash"));
  auto ss = yacl::crypto::RandVec<uint128_t>(cuckoolen);
  size_t sender_bin_size = elem_hashes.size();
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(sender_bin_size),
                 "sender_bin_size");
  std::vector<uint128_t> values1(sender_bin_size);
  std::vector<uint128_t> values2(sender_bin_size);
  std::vector<uint128_t> values3(sender_bin_size);
  duplicate_elements(elem_hashes, values1, values2, values3, ss, cuckoolen);
  size_t weight = 3;
  // statistical security parameter
  size_t ssp = 40;
  okvs::Baxos sendbaxos;
  okvs::Baxos recvbaxos;
  sendbaxos.Init(sender_bin_size, sender_bin_size, weight, ssp,
                 okvs::PaxosParam::DenseType::GF128, seed);
  recvbaxos.Init(cuckoolen, cuckoolen, weight, ssp,
                 okvs::PaxosParam::DenseType::GF128, seed);

  // opprf::OPPRFSend(ctx, keys, values, sendbaxos,recvbaxos);
  size_t recvokvssize =
      DeserializeUint128(ctx->Recv(ctx->PrevRank(), "baxos.size"));

  const auto codetype = yacl::crypto::CodeType::Silver5;
  std::vector<uint128_t> b(recvokvssize);
  uint128_t delta = 0;
  auto volesender = std::async([&] {
    auto sv_sender = yacl::crypto::SilentVoleSender(codetype);
    sv_sender.Send(ctx, absl::MakeSpan(b));
    delta = sv_sender.GetDelta();
  });
  volesender.get();

  std::vector<uint128_t> aprime(recvokvssize);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive A' = P+A");
  YACL_ENFORCE(buf.size() == int64_t(recvokvssize * sizeof(uint128_t)));

  std::memcpy(aprime.data(), buf.data(), buf.size());
  okvs::Galois128 delta_gf128(delta);
  std::vector<uint128_t> k(recvokvssize);
  yacl::parallel_for(0, recvokvssize, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      k[idx] = b[idx] ^ (delta_gf128 * aprime[idx]).get<uint128_t>(0);
    }
  });

  std::vector<uint128_t> sendermasks(sender_bin_size);
  std::vector<uint128_t> sendermasks1(sender_bin_size);
  std::vector<uint128_t> sendermasks2(sender_bin_size);
  std::vector<uint128_t> sendermasks3(sender_bin_size);
  recvbaxos.Decode(absl::MakeSpan(elem_hashes), absl::MakeSpan(sendermasks),
                   absl::MakeSpan(k), 8);

  yacl::parallel_for(0, sender_bin_size, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      auto mask =
          sendermasks[idx] ^ (delta_gf128 * elem_hashes[idx]).get<uint128_t>(0);
      sendermasks1[idx] = mask ^ values1[idx];
      sendermasks2[idx] = mask ^ values2[idx];
      sendermasks3[idx] = mask ^ values3[idx];
    }
  });

  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(sendbaxos.size()),
                 "the size of p1");
  std::vector<uint128_t> p11(sendbaxos.size());
  std::vector<uint128_t> p12(sendbaxos.size());
  std::vector<uint128_t> p13(sendbaxos.size());
  sendbaxos.Solve(absl::MakeSpan(elem_hashes), absl::MakeSpan(sendermasks1),
                  absl::MakeSpan(p11), nullptr, 8);
  sendbaxos.Solve(absl::MakeSpan(elem_hashes), absl::MakeSpan(sendermasks2),
                  absl::MakeSpan(p12), nullptr, 8);
  sendbaxos.Solve(absl::MakeSpan(elem_hashes), absl::MakeSpan(sendermasks2),
                  absl::MakeSpan(p13), nullptr, 8);

  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(p11.data(), p11.size() * sizeof(uint128_t)),
      "Send p11");
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(p12.data(), p12.size() * sizeof(uint128_t)),
      "Send p12");
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(p13.data(), p13.size() * sizeof(uint128_t)),
      "Send p13");

  auto result = elem_hashes;
  return result;
}

void OPPRFPSUSend(const std::shared_ptr<yacl::link::Context>& ctx,
                  std::vector<uint128_t>& elem_hashes, uint128_t seed) {
  CuckooHash cuckooHash(elem_hashes.size());
  // 插入数据到哈希表中
  cuckooHash.Insert(elem_hashes);
  // 打印插入后的哈希表数据
  cuckooHash.FillRandom();
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(cuckooHash.cuckoolen_),
                 "the size of cuckoohash");
  size_t sender_bin_size =
      DeserializeUint128(ctx->Recv(ctx->PrevRank(), "sender_bin_size"));
  size_t recv_bin_size = cuckooHash.cuckoolen_;
  size_t weight = 3;
  // statistical security parameter
  size_t ssp = 40;
  okvs::Baxos sendbaxos;
  okvs::Baxos recvbaxos;
  sendbaxos.Init(sender_bin_size, sender_bin_size, weight, ssp,
                 okvs::PaxosParam::DenseType::GF128, seed);
  recvbaxos.Init(recv_bin_size, recv_bin_size, weight, ssp,
                 okvs::PaxosParam::DenseType::GF128, seed);

  uint128_t recvokvssize = recvbaxos.size();
  // VOLE
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(recvokvssize),
                 "baxos.size");
  // VOLE
  const auto codetype = yacl::crypto::CodeType::Silver5;
  std::vector<uint128_t> a(recvokvssize);
  std::vector<uint128_t> c(recvokvssize);
  auto volereceiver = std::async([&] {
    auto sv_receiver = yacl::crypto::SilentVoleReceiver(codetype);
    sv_receiver.Recv(ctx, absl::MakeSpan(a), absl::MakeSpan(c));
  });

  // Encode
  std::vector<uint128_t> p(recvokvssize);
  recvbaxos.Solve(absl::MakeSpan(cuckooHash.bins_),
                  absl::MakeSpan(cuckooHash.bins_), absl::MakeSpan(p), nullptr,
                  8);
  volereceiver.get();

  std::vector<uint128_t> aprime(recvokvssize);

  yacl::parallel_for(0, aprime.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      aprime[idx] = a[idx] ^ p[idx];
    }
  });

  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(aprime.data(), recvokvssize * sizeof(uint128_t)),
      "Send A' = P+A");

  std::vector<uint128_t> receivermasks(cuckooHash.cuckoolen_);
  recvbaxos.Decode(absl::MakeSpan(cuckooHash.bins_),
                   absl::MakeSpan(receivermasks), absl::MakeSpan(c), 8);

  size_t sizep1 =
      DeserializeUint128(ctx->Recv(ctx->PrevRank(), "the size of p1"));

  std::vector<uint128_t> p11(sizep1);
  std::vector<uint128_t> p12(sizep1);
  std::vector<uint128_t> p13(sizep1);
  auto buf1 = ctx->Recv(ctx->PrevRank(), "Receive p1");
  YACL_ENFORCE(buf1.size() == int64_t(sizep1 * sizeof(uint128_t)));
  std::memcpy(p11.data(), buf1.data(), buf1.size());
  auto buf2 = ctx->Recv(ctx->PrevRank(), "Receive p2");
  YACL_ENFORCE(buf2.size() == int64_t(sizep1 * sizeof(uint128_t)));
  std::memcpy(p12.data(), buf2.data(), buf2.size());
  auto buf3 = ctx->Recv(ctx->PrevRank(), "Receive p3");
  YACL_ENFORCE(buf3.size() == int64_t(sizep1 * sizeof(uint128_t)));
  std::memcpy(p13.data(), buf3.data(), buf3.size());
  std::vector<uint128_t> ts1(cuckooHash.bins_.size());
  std::vector<uint128_t> ts2(cuckooHash.bins_.size());
  std::vector<uint128_t> ts3(cuckooHash.bins_.size());
  sendbaxos.Decode(absl::MakeSpan(cuckooHash.bins_), absl::MakeSpan(ts1),
                   absl::MakeSpan(p11), 8);
  yacl::parallel_for(0, cuckooHash.cuckoolen_, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      ts1[idx] = ts1[idx] ^ receivermasks[idx];
    }
  });
  sendbaxos.Decode(absl::MakeSpan(cuckooHash.bins_), absl::MakeSpan(ts2),
                   absl::MakeSpan(p12), 8);
  yacl::parallel_for(0, cuckooHash.cuckoolen_, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      ts2[idx] = ts2[idx] ^ receivermasks[idx];
    }
  });
  sendbaxos.Decode(absl::MakeSpan(cuckooHash.bins_), absl::MakeSpan(ts3),
                   absl::MakeSpan(p13), 8);
  yacl::parallel_for(0, cuckooHash.cuckoolen_, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      ts3[idx] = ts3[idx] ^ receivermasks[idx];
    }
  });
}