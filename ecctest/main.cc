
#include <cstddef>
#include <iostream>
#include <memory>
#include <vector>

#include "yacl/base/int128.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/link/link.h"
#include "yacl/utils/parallel.h"
#include <set>
#include <tuple>
#include <cstdlib>
#include <ctime>

// 使用 std::tuple 存储三元组
using Triple = std::tuple<uint32_t, uint32_t, uint32_t>;

inline uint32_t GetSubBytesAsUint32(const yacl::Buffer& bytes, size_t start,
                             size_t end) {
  uint32_t result = 0;
  for (size_t i = start; i < end; ++i) {
    result = (result << 8) | bytes.data<uint8_t>()[i];
  }
  return result;
}

Triple sort_triple(Triple t) {
    // 把 tuple 转换为数组，便于排序
    uint32_t arr[3] = {std::get<0>(t), std::get<1>(t), std::get<2>(t)};
    std::sort(arr, arr + 3); // 对数组排序
    return std::make_tuple(arr[0], arr[1], arr[2]); // 将排序后的数组重新生成 tuple
}

// 假设 yacl::Buffer 提供 .data() 和 .size() 方法
void SerializeVector(const std::vector<yacl::Buffer>& XS, const std::string& filename) {
    std::ofstream outfile(filename, std::ios::binary);

    if (!outfile.is_open()) {
        std::cerr << "无法打开文件: " << filename << std::endl;
        return;
    }

    // 写入向量大小
    size_t vector_size = XS.size();
    outfile.write(reinterpret_cast<const char*>(&vector_size), sizeof(vector_size));

    // 遍历并序列化每个 yacl::Buffer
    for (const auto& buffer : XS) {
        size_t buffer_size = buffer.size(); // 假设 buffer.size() 返回字节大小
        outfile.write(reinterpret_cast<const char*>(&buffer_size), sizeof(buffer_size)); // 写入 buffer 大小
        outfile.write(reinterpret_cast<const char*>(buffer.data()), buffer_size); // 写入 buffer 数据
    }

    outfile.close();
    std::cout << "序列化完成并保存到文件: " << filename << std::endl;
}

void Insert(std::vector<yacl::Buffer> data,uint32_t cuckoolen) {
    std::set<Triple> unique_triples;
    for (size_t i = 0; i < data.size(); ++i) {

        uint32_t a = GetSubBytesAsUint32(data[i], 0, 4) % cuckoolen;
        uint32_t b= GetSubBytesAsUint32(data[i], 8, 12) % cuckoolen;
        uint32_t c = GetSubBytesAsUint32(data[i], 16, 20) % cuckoolen;
        Triple new_triple = std::make_tuple(a, b, c);
        new_triple = sort_triple(new_triple); // 对三元组排序
        if (unique_triples.find(new_triple) != unique_triples.end()) {
            std::cout << "发现重复的三元组: (" << a << ", " << b << ", " << c << ")" << std::endl;
            break;
        } else {
            unique_triples.insert(new_triple);
            std::cout << "生成三元组: (" << a << ", " << b << ", " << c << ")" << std::endl;
        }
  }
}


int main(){
    auto ec = yacl::crypto::EcGroupFactory::Instance().Create(/* curve name */ "secp256k1");
    size_t n = 1<<24;
    std::vector<yacl::Buffer> XS(n);
    if (!ec) {
      throw std::runtime_error("EcGroup not initialized");
    }
    yacl::parallel_for(1, n + 1, [&](int64_t beg, int64_t end) {
      for (int64_t i = beg; i < end; ++i) {
        yacl::math::MPInt value(i);
        auto point = ec->MulBase(value);
        // 获取横坐标作为键
        auto affine_point = ec->GetAffinePoint(point);
        auto key = affine_point.x.ToMagBytes(yacl::Endian::native);
        XS[i - 1] = key;
      }
    });
    //SerializeVector(XS, "serialized_data.bin");
    uint32_t cuckoolen = static_cast<uint32_t>(n * 1.01);
    Insert(XS,cuckoolen);
    return 0;

}