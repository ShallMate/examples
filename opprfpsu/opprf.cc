
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

#include "examples/opprfpsu/opprf.h"

#include <iostream>
#include <vector>

#include "examples/opprfpsu/okvs/galois128.h"

#include "yacl/base/int128.h"
#include "yacl/kernel/algorithms/silent_vole.h"
#include "yacl/utils/parallel.h"

namespace opprf {

std::vector<uint128_t> OPPRFRecv(
    const std::shared_ptr<yacl::link::Context>& ctx,
    std::vector<uint128_t>& elem_hashes, okvs::Baxos sendbaxos,
    okvs::Baxos recvbaxos) {
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
  recvbaxos.Solve(absl::MakeSpan(elem_hashes), absl::MakeSpan(elem_hashes),
                  absl::MakeSpan(p), nullptr, 8);
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

  std::vector<uint128_t> receivermasks(elem_hashes.size());
  recvbaxos.Decode(absl::MakeSpan(elem_hashes), absl::MakeSpan(receivermasks),
                   absl::MakeSpan(c), 8);

  size_t sizep1 =
      DeserializeUint128(ctx->Recv(ctx->PrevRank(), "the size of p1"));

  std::vector<uint128_t> p1(sizep1);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive p1");
  YACL_ENFORCE(buf.size() == int64_t(sizep1 * sizeof(uint128_t)));
  std::memcpy(p1.data(), buf.data(), buf.size());
  std::vector<uint128_t> result(elem_hashes.size());
  sendbaxos.Decode(absl::MakeSpan(elem_hashes), absl::MakeSpan(result),
                   absl::MakeSpan(p1), 8);
  yacl::parallel_for(0, elem_hashes.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      result[idx] = result[idx] ^ receivermasks[idx];
    }
  });
  return result;
}

void OPPRFSend(const std::shared_ptr<yacl::link::Context>& ctx,
               std::vector<uint128_t>& elem_hashes,
               std::vector<uint128_t>& elem_hashes1, okvs::Baxos sendbaxos,
               okvs::Baxos recvbaxos) {
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

  std::vector<uint128_t> sendermasks(elem_hashes.size());
  recvbaxos.Decode(absl::MakeSpan(elem_hashes), absl::MakeSpan(sendermasks),
                   absl::MakeSpan(k), 8);

  yacl::parallel_for(0, elem_hashes.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sendermasks[idx] = sendermasks[idx] ^
                         (delta_gf128 * elem_hashes[idx]).get<uint128_t>(0) ^
                         elem_hashes1[idx];
    }
  });

  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(sendbaxos.size()),
                 "the size of p1");

  std::vector<uint128_t> p1(sendbaxos.size());
  sendbaxos.Solve(absl::MakeSpan(elem_hashes), absl::MakeSpan(sendermasks),
                  absl::MakeSpan(p1), nullptr, 8);

  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(p1.data(), p1.size() * sizeof(uint128_t)),
      "Send p1");
}

}  // namespace opprf