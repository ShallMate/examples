#include <iostream>
#include "absl/types/span.h"
#include "yacl/base/int128.h"
#include "yacl/utils/cuckoo_index.h"  // 假设已经包含了相关的头文件
#include <vector>
#include "yacl/utils/parallel.h"
#include "yacl/base/int128.h"
#include "yacl/kernel/algorithms/silent_vole.h"
#include "yacl/utils/parallel.h"

using namespace yacl::crypto;


std::vector<uint128_t> CreateRangeItems(size_t begin, size_t size) {
  std::vector<uint128_t> ret;
  for (size_t i = 0; i < size; ++i) {
    ret.push_back(yacl::crypto::Blake3_128(std::to_string(begin + i)));
  }
  return ret;
}

int main() {
    // 1. 定义 CuckooIndex 的配置选项
    yacl::CuckooIndex::Options options;
    options.num_input = 1<<20;          // 期望输入 1000 个元素
    options.num_stash = 0;            // 设置 stash 容量
    options.num_hash = 3;              // 使用 3 个哈希函数
    options.scale_factor = 1.27;        // 扩展因子

    // 2. 创建 CuckooIndex 对象
    yacl::CuckooIndex cuckoo_index(options);

    auto set = CreateRangeItems(10,options.num_input);

    // 3. 构建要插入的哈希值列表 (假设我们已经有了这些值)
    std::vector<yacl::CuckooIndex::HashType> hash_codes = {set};

    // 4. 插入数据
    cuckoo_index.Insert(absl::MakeSpan(hash_codes));

    // 5. 调用 SanityCheck 进行调试检查
    cuckoo_index.SanityCheck();

    // 6. 打印插入的 bin 信息 (用于调试)
    const std::vector<yacl::CuckooIndex::Bin>& bins = cuckoo_index.bins();
    for (size_t i = 0; i < bins.size(); ++i) {
        if (!bins[i].IsEmpty()) {
            std::cout << "Bin " << i << ": InputIdx = " << bins[i].InputIdx()
                      << ", HashIdx = " << static_cast<int>(bins[i].HashIdx()) << std::endl;
        }
    }

    return 0;
}