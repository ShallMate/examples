#include <cstdint>
#include <iostream>
#include <vector>

#include "examples/upsi/ecdhpsi/ecdh_psi.h"
#include "examples/upsi/ecdhpsi/receiver.h"
#include "examples/upsi/ecdhpsi/sender.h"
#include "examples/upsi/psu/psu.h"
#include "examples/upsi/rr22/okvs/baxos.h"
#include "examples/upsi/rr22/rr22.h"
#include "examples/upsi/upsi.h"

#include "yacl/base/int128.h"
#include "yacl/kernel/algorithms/silent_vole.h"

using namespace yacl::crypto;
using namespace std;

std::vector<uint128_t> CreateRangeItems(size_t begin, size_t size) {
  std::vector<uint128_t> ret;
  for (size_t i = 0; i < size; ++i) {
    ret.push_back(yacl::crypto::Blake3_128(std::to_string(begin + i)));
  }
  return ret;
}

std::vector<std::string> CreateRangeItemsDH(size_t begin, size_t size) {
  std::vector<std::string> ret;
  for (size_t i = 0; i < size; i++) {
    ret.push_back(std::to_string(begin + i));
  }
  return ret;
}

void RunRR22() {
  const uint64_t num = 1 << 22;
  size_t bin_size = num;
  size_t weight = 3;
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

  std::future<std::vector<uint128_t>> rr22_sender =
      std::async(std::launch::async,
                 [&] { return rr22::RR22PsiSend(lctxs[0], items_a, baxos); });

  std::future<std::vector<uint128_t>> rr22_receiver =
      std::async(std::launch::async,
                 [&] { return rr22::RR22PsiRecv(lctxs[1], items_b, baxos); });

  auto psi_result_sender = rr22_sender.get();
  auto psi_result = rr22_receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;

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

void RunUPSI() {
  const uint64_t num = 1 << 24;
  const uint64_t addnum = 1 << 12;
  const uint64_t subnum = 1 << 12;
  size_t bin_size = num;
  size_t weight = 3;
  size_t ssp = 40;
  okvs::Baxos baxos;
  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());
  uint128_t seed;
  prng.Fill(absl::MakeSpan(&seed, 1));
  SPDLOG_INFO("items_num:{}, bin_size:{}", num, bin_size);
  baxos.Init(num, bin_size, weight, ssp, okvs::PaxosParam::DenseType::GF128,
             seed);

  SPDLOG_INFO("baxos.size(): {}", baxos.size());

  std::vector<uint128_t> X = CreateRangeItems(addnum, num);
  std::vector<uint128_t> Y = CreateRangeItems(addnum, num);
  std::vector<uint128_t> Xadd = CreateRangeItems(0, addnum);
  std::vector<uint128_t> Yadd = CreateRangeItems(0, addnum);
  std::vector<uint128_t> Xsub = CreateRangeItems(num - subnum, num);
  std::vector<uint128_t> Ysub = CreateRangeItems(num - subnum, num);

  auto lctxs = yacl::link::test::SetupWorld(2);  // setup network
  std::future<std::vector<uint128_t>> rr22_sender = std::async(
      std::launch::async, [&] { return BasePsiSend(lctxs[0], X, baxos); });
  std::future<std::vector<uint128_t>> rr22_receiver = std::async(
      std::launch::async, [&] { return BasePsiRecv(lctxs[1], Y, baxos); });
  auto psi_result_sender = rr22_sender.get();
  auto psi_result = rr22_receiver.get();
  std::set<uint128_t> intersection_sender(psi_result_sender.begin(),
                                          psi_result_sender.end());
  std::set<uint128_t> intersection_receiver(psi_result.begin(),
                                            psi_result.end());
  if (intersection_sender == intersection_receiver) {
    std::cout << "The base PSI finish." << std::endl;
  } else {
    std::cout << "The base PSI error." << std::endl;
  }
  auto start_time = std::chrono::high_resolution_clock::now();
  EcdhReceiver yaddreceiver;
  EcdhSender yaddsender;
  yaddsender.UpdatePRFs(absl::MakeSpan(X));
  EcdhReceiver xaddreceiver;
  EcdhSender xaddsender;
  xaddsender.UpdatePRFs(absl::MakeSpan(Y));
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Setup time: " << duration.count() << " seconds" << std::endl;

  auto newlctxs = yacl::link::test::SetupWorld(2);  // setup network
  auto start_time1 = std::chrono::high_resolution_clock::now();
  std::future<std::vector<uint128_t>> upsisender =
      std::async(std::launch::async, [&] {
        return UPsiSend(newlctxs[0], Y, Yadd, Ysub, yaddreceiver, xaddsender,
                        intersection_sender);
      });

  std::future<std::vector<uint128_t>> upsireceiver =
      std::async(std::launch::async, [&] {
        return UPsiRecv(newlctxs[1], X, Xadd, Xsub, xaddreceiver, yaddsender,
                        intersection_receiver);
      });
  auto upsi_result_sender = upsisender.get();
  auto upsi_result_receiver = upsireceiver.get();
  auto end_time1 = std::chrono::high_resolution_clock::now();
  std::set<uint128_t> upsi_intersection_sender(upsi_result_sender.begin(),
                                               upsi_result_sender.end());
  std::set<uint128_t> upsi_intersection_receiver(upsi_result_receiver.begin(),
                                                 upsi_result_receiver.end());
  if (upsi_result_sender == upsi_result_receiver) {
    std::cout << "The uPSI finish." << std::endl;
  } else {
    std::cout << "The uPSI error." << std::endl;
  }
  std::chrono::duration<double> duration1 = end_time1 - start_time1;
  std::cout << "UPSI time: " << duration1.count() << " seconds" << std::endl;

  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = newlctxs[0]->GetStats();
  auto receiver_stats = newlctxs[1]->GetStats();
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

int RunPSU() {
  const int kWorldSize = 2;
  auto contexts = yacl::link::test::SetupWorld(kWorldSize);
  auto n = 1 << 14;
  std::vector<uint128_t> items_a = CreateRangeItems(0, n);
  std::vector<uint128_t> items_b = CreateRangeItems(1, n);
  auto start_time = std::chrono::high_resolution_clock::now();
  std::future<std::vector<uint128_t>> krtwpsu_sender = std::async(
      std::launch::async, [&] { return KrtwPsuSend(contexts[0], items_a); });
  std::future<std::vector<uint128_t>> krtwpsu_receiver = std::async(
      std::launch::async, [&] { return KrtwPsuRecv(contexts[1], items_b); });
  krtwpsu_sender.get();
  auto psu_result = krtwpsu_receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  std::sort(psu_result.begin(), psu_result.end());
  std::set<uint128_t> union_set;
  union_set.insert(items_a.begin(), items_a.end());
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

int RunEcdhPsi() {
  size_t s_n = 1 << 20;
  size_t r_n = 1 << 20;
  auto x = CreateRangeItemsDH(0, s_n);
  auto y = CreateRangeItemsDH(3, r_n);
  auto lctxs = yacl::link::test::SetupWorld(2);  // setup network
  auto start_time = std::chrono::high_resolution_clock::now();
  std::future<void> sender =
      std::async(std::launch::async, [&] { EcdhPsiSend(lctxs[0], x, r_n); });
  std::future<std::vector<size_t>> receiver = std::async(
      std::launch::async, [&] { return EcdhPsiRecv(lctxs[1], y, s_n); });
  sender.get();
  auto z = receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  ;
  std::cout << "The intersection size is " << z.size() << std::endl;
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

int RunAEcdhPsi() {
  size_t s_n = 1 << 18;
  size_t r_n = 1 << 10;
  auto x = CreateRangeItems(200, s_n);
  // auto xadd = CreateRangeItems(100, 100);
  auto y = CreateRangeItems(100, r_n);
  auto lctxs = yacl::link::test::SetupWorld(2);  // setup network
  EcdhReceiver receiver;
  EcdhSender sender;
  sender.UpdatePRFs(absl::MakeSpan(x));
  // sender.UpdatePRFs(absl::MakeSpan(xadd));
  auto start_time = std::chrono::high_resolution_clock::now();
  std::future<void> sendertask = std::async(
      std::launch::async, [&] { sender.EcdhPsiSend(lctxs[0], r_n); });
  std::future<std::vector<uint128_t>> receivertask = std::async(
      std::launch::async, [&] { return receiver.EcdhPsiRecv(lctxs[1], y); });
  sendertask.get();
  auto z = receivertask.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  ;
  std::cout << "The intersection size is " << z.size() << std::endl;
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

int main() {
  // RunAEcdhPsi();
  // RunRR22();
  // RunPSU();
  RunUPSI();
}
