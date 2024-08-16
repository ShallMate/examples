#include <iostream>
#include <vector>

#include "yacl/link/test_util.h"
#include "yacl/kernel/algorithms/softspoken_ote.h"

using namespace yacl::crypto;
using namespace std;

constexpr size_t kNumInkpOT = 1<<24;

void OTRecv(
    const std::shared_ptr<yacl::link::Context>& ctx) {
  auto ss_receiver = yacl::crypto::SoftspokenOtExtReceiver();
  auto store = ss_receiver.GenRot(ctx, kNumInkpOT);
}

void OTSend(const std::shared_ptr<yacl::link::Context>& ctx) {
  auto ss_sender = yacl::crypto::SoftspokenOtExtSender();
  auto store = ss_sender.GenRot(ctx, kNumInkpOT);
}

int main() {
  // 确保链接上下文定义正确
  const int kWorldSize = 2;
  auto contexts = yacl::link::test::SetupWorld(kWorldSize);


  auto start_time = std::chrono::high_resolution_clock::now();
  std::future<void> ot_sender = std::async(std::launch::async, [&] {
    OTSend(contexts[0]);
  });

  std::future<void> ot_receiver = std::async(std::launch::async, [&] {
    return OTRecv(contexts[1]);
  });

  ot_sender.get();
  ot_receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Send and Receive operations took " << duration.count() << " seconds." << std::endl;


  auto sender_stats = contexts[0]->GetStats();
  auto receiver_stats = contexts[1]->GetStats();

  std::cout << "Sender sent bytes: " << sender_stats->sent_bytes.load() << std::endl;
  std::cout << "Sender received bytes: " << sender_stats->recv_bytes.load() << std::endl;
  std::cout << "Receiver sent bytes: " << receiver_stats->sent_bytes.load() << std::endl;
  std::cout << "Receiver received bytes: " << receiver_stats->recv_bytes.load() << std::endl;
}
