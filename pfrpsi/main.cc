// Copyright 2024 Guowei Ling.
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

#include <cstddef>
#include <iostream>
#include <vector>

#include "examples/pfrpsi/okvs/baxos.h"
#include "examples/pfrpsi/volepfrpsi.h"

#include "yacl/base/int128.h"
#include "yacl/kernel/algorithms/silent_vole.h"
#include "yacl/link/test_util.h"
#include "yacl/utils/parallel.h"
#include <fstream>

using namespace yacl::crypto;
using namespace std;

std::vector<uint128_t> CreateRangeItems(size_t begin, size_t size) {
  std::vector<uint128_t> ret;
  for (size_t i = 0; i < size; ++i) {
    ret.push_back(yacl::crypto::Blake3_128(std::to_string(begin + i)));
  }
  return ret;
}



void RunVolePfrpsi() {
  size_t n = 1048576;
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
      okvs::Galois128 delta_a(A[idx]);
      C2[idx] = C1[idx] ^ (delta_a * B[idx]).get<uint128_t>(0);
    }
  });
  size_t bin_size = n;
  size_t weight = 3;
  size_t ssp = 40;
  okvs::Baxos baxos;
  prng.Fill(absl::MakeSpan(&seed, 1));
  SPDLOG_INFO("items_num:{}, bin_size:{}", n, bin_size);
  baxos.Init(n, bin_size, weight, ssp, okvs::PaxosParam::DenseType::GF128,
             seed);
  SPDLOG_INFO("baxos.size(): {}", baxos.size());
  std::vector<uint128_t> items_a = CreateRangeItems(0, n);
  std::vector<uint128_t> items_b = CreateRangeItems(0, n);
  auto lctxs = yacl::link::test::SetupWorld(2);  // setup network
  auto start_time = std::chrono::high_resolution_clock::now();
  std::future<void> sender = std::async(
      std::launch::async, [&] { VOLEPFRPSI::PRFPSISend(lctxs[0], items_a, baxos,B,C2); });
  std::future<std::vector<uint128_t>> receiver =
      std::async(std::launch::async,
                 [&] { return VOLEPFRPSI::PRFPSIRecv(lctxs[1], items_b, baxos,A,C1); });
  sender.get();
  auto psi_result = receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  ;
  std::sort(psi_result.begin(), psi_result.end());
  std::cout<<"The intersection size is "<<psi_result.size()<<std::endl;
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
            << bytesToMB(receiver_stats->sent_bytes.load())+bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
}

int main(){
  RunVolePfrpsi();
}