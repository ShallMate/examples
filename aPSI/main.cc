
// Copyright 2025 Guowei Ling
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

#include <apsi/network/stream_channel.h>
#include <apsi/sender.h>
#include <json/json.h>

#include <cstddef>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "aPSI.h"
#include "apsi/oprf/oprf_receiver.h"
#include "apsi/receiver.h"
#include "apsi/util/utils.h"

#include "yacl/base/int128.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/utils/parallel.h"
#include "yacl/utils/serialize.h"

using namespace std;
using namespace apsi;

int main() {
  // Use the maximum number of threads available on the machine
  // ThreadPoolMgr::SetThreadCount(std::thread::hardware_concurrency());
  ThreadPoolMgr::SetThreadCount(std::thread::hardware_concurrency());
  // Full logging to console
  // Log::SetLogLevel(Log::Level::all);
  // Log::SetConsoleDisabled(false);
  size_t ns = 1 << 20;
  size_t nr = 1 << 12;
  std::vector<uint128_t> raw_sender_items = CreateRangeItems(1, ns);
  APSI instance("/home/lgw/yacl/examples/aPSI/params.json");
  instance.insertItems(raw_sender_items);
  // instance.printParams();
  vector<uint128_t> raw_receiver_items = CreateRangeItems(1, nr);
  auto start_time = std::chrono::high_resolution_clock::now();
  auto intersection = instance.APsiRun(raw_receiver_items);
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Intersection size: " << intersection.size() << std::endl;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  cout << "Communication bytes: "
       << instance.channel_->bytes_received() / (1024.0 * 1024.0) << " MB"
       << endl;
  return 0;
}
