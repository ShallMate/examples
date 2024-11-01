#include <iostream>
#include <vector>

#include "examples/mini/mini_psi.h"

#include "yacl/link/test_util.h"

std::vector<std::string> CreateRangeItems(size_t begin, size_t size) {
  std::vector<std::string> ret;
  for (size_t i = 0; i < size; i++) {
    ret.push_back(std::to_string(begin + i));
  }
  return ret;
}

int RunEcdhPsi() {
  size_t s_n = 1 << 13;
  size_t r_n = 1 << 13;
  auto x = CreateRangeItems(0, s_n);
  auto y = CreateRangeItems(3, r_n);
  auto lctxs = yacl::link::test::SetupWorld(2);  // setup network
  auto start_time = std::chrono::high_resolution_clock::now();
  std::future<void> sender =
      std::async(std::launch::async, [&] { MiniPsiSend(lctxs[0], x); });
  std::future<std::vector<std::string>> receiver =
      std::async(std::launch::async, [&] { return MiniPsiRecv(lctxs[1], y); });
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

int main() { RunEcdhPsi(); }