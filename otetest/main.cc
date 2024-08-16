#include <iostream>
#include <vector>

#include "yacl/link/test_util.h"
#include "yacl/kernel/algorithms/softspoken_ote.h"

using namespace yacl::crypto;
using namespace std;

constexpr size_t kNumInkpOT = 1<<20;

void OTRecv(
    const std::shared_ptr<yacl::link::Context>& ctx) {
  auto ss_receiver = yacl::crypto::SoftspokenOtExtReceiver();
  auto store = ss_receiver.GenRot(ctx, kNumInkpOT);
  cout<<store.GetBlock(1)<<endl;
}

void OTSend(const std::shared_ptr<yacl::link::Context>& ctx) {
  auto ss_sender = yacl::crypto::SoftspokenOtExtSender();
  auto store = ss_sender.GenRot(ctx, kNumInkpOT);

}

int main() {
  // 确保链接上下文定义正确
  const int kWorldSize = 2;
  auto contexts = yacl::link::test::SetupWorld(kWorldSize);



  std::future<void> krtwpsu_sender = std::async(std::launch::async, [&] {
    OTSend(contexts[0]);
  });

  std::future<void> krtwpsu_receiver = std::async(std::launch::async, [&] {
    return OTRecv(contexts[1]);
  });

  krtwpsu_sender.get();
  krtwpsu_receiver.get();
}
