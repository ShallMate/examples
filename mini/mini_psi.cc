// Copyright 2022 Ant Group Co., Ltd.
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

#include "examples/mini/mini_psi.h"

#include <future>
#include <map>
#include <random>
#include <set>
#include <unordered_set>

#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "omp.h"
#include "openssl/crypto.h"
#include "openssl/rand.h"
#include "spdlog/spdlog.h"

extern "C" {
#include "curve25519.h"
}

#include "yacl/base/exception.h"
#include "yacl/crypto/block_cipher/symmetric_crypto.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/crypto/tools/prg.h"
#include "yacl/utils/parallel.h"

#include "examples/mini/polynomial.h"
#include "yacl/utils/cuckoo_index.h"

struct PsiDataBatch {
  uint32_t item_num = 0;
  std::string flatten_bytes;
  int32_t batch_index = 0;
  bool is_last_batch = false;
  std::string type;

  // 序列化为字符串形式
  std::string Serialize() const {
    std::string serialized_data;

    // 序列化 item_num
    serialized_data.append(reinterpret_cast<const char*>(&item_num), sizeof(item_num));

    // 序列化 flatten_bytes 的长度和内容
    uint32_t flatten_bytes_size = flatten_bytes.size();
    serialized_data.append(reinterpret_cast<const char*>(&flatten_bytes_size), sizeof(flatten_bytes_size));
    serialized_data.append(flatten_bytes);

    // 序列化 is_last_batch
    serialized_data.append(reinterpret_cast<const char*>(&is_last_batch), sizeof(is_last_batch));

    return serialized_data;
  }

  // 反序列化 Buffer 数据
  static PsiDataBatch Deserialize(const yacl::Buffer& buf) {
    PsiDataBatch batch;
    size_t offset = 0;

    // 将 Buffer 数据复制到 std::vector<uint8_t>
    std::vector<uint8_t> buffer_data(buf.size());
    std::memcpy(buffer_data.data(), buf.data(), buf.size());

    // 将 std::vector<uint8_t> 转换为 std::string
    std::string serialized_data(buffer_data.begin(), buffer_data.end());

    // 反序列化 item_num
    std::memcpy(&batch.item_num, serialized_data.data() + offset, sizeof(batch.item_num));
    offset += sizeof(batch.item_num);

    // 反序列化 flatten_bytes 的长度和内容
    uint32_t flatten_bytes_size;
    std::memcpy(&flatten_bytes_size, serialized_data.data() + offset, sizeof(flatten_bytes_size));
    offset += sizeof(flatten_bytes_size);

    batch.flatten_bytes = serialized_data.substr(offset, flatten_bytes_size);
    offset += flatten_bytes_size;

    // 反序列化 is_last_batch
    std::memcpy(&batch.is_last_batch, serialized_data.data() + offset, sizeof(batch.is_last_batch));

    return batch;
  }
};

inline constexpr size_t kEcdhPsiBatchSize = 4096;

// Ecc256 requires 32 bytes.
inline constexpr size_t kKeySize = 32;
inline constexpr size_t kHashSize = kKeySize;

// The final comparison bytes.
// Hongcheng suggested that 90 bits would be enough. Here we give 96 bits.
//
// The least significant bits(LSB) of g^{ab} are globally indistinguishable from
// a random bit-string, Reference:
// Optimal Randomness Extraction from a Diffie-Hellman Element
// EUROCRYPT 2009 https://link.springer.com/chapter/10.1007/978-3-642-01001-9_33
//
inline constexpr size_t kFinalCompareBytes = 12;

constexpr uint32_t kLinkRecvTimeout = 30 * 60 * 1000;
// first prime over 2^256, used as module for polynomial interpolate
std::string kPrimeOver256bHexStr =
    "010000000000000000000000000000000000000000000000000000000000000129";




std::vector<std::string> HashInputs(const std::vector<std::string>& items) {
  std::vector<std::string> ret(items.size());
  yacl::parallel_for(0, items.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      auto hash = yacl::crypto::Sha256(items[idx]);
      ret[idx].resize(hash.size());
      std::memcpy(ret[idx].data(), hash.data(), hash.size());
    }
  });
  return ret;
}

struct MiniPsiSendCtx {
  MiniPsiSendCtx() {
    yacl::crypto::Prg<uint64_t> prg(0, yacl::crypto::PRG_MODE::kAesEcb);
    prg.Fill(absl::MakeSpan(private_key.data(), kKeySize));

    curve25519_donna_basepoint(static_cast<unsigned char*>(public_key.data()),
                               private_key.data());

    uint128_t aes_key = yacl::crypto::Blake3_128(public_key);
    aes_ecb = std::make_shared<yacl::crypto::SymmetricCrypto>(
        yacl::crypto::SymmetricCrypto::CryptoType::AES128_ECB, aes_key, 0);

    prime256_str = absl::HexStringToBytes(kPrimeOver256bHexStr);
  }

  void RecvPolynomialCoeff(
      const std::shared_ptr<yacl::link::Context>& link_ctx) {
    size_t batch_count = 0;

    yacl::link::RecvTimeoutGuard guard(link_ctx, kLinkRecvTimeout);
    while (true) {
      const auto tag = fmt::format("MINI-PSI:X^A:{}", batch_count);
      PsiDataBatch coeff_batch =
          PsiDataBatch::Deserialize(link_ctx->Recv(link_ctx->NextRank(), tag));
      // Fetch y^b.
      YACL_ENFORCE(coeff_batch.flatten_bytes.size() % kHashSize == 0);
      size_t num_items = coeff_batch.flatten_bytes.size() / kHashSize;

      if (num_items > 0) {
        absl::string_view flatten_bytes = coeff_batch.flatten_bytes;

        for (size_t i = 0; i < num_items; ++i) {
          polynomial_coeff.emplace_back(
              flatten_bytes.substr(i * kHashSize, kHashSize));
        }
      }

      if (coeff_batch.is_last_batch) {
        break;
      }
      batch_count++;
    }
  }

  void EvalPolynomial(const std::vector<std::string>& items) {
    polynomial_eval_values.resize(items.size());
    masked_values.resize(items.size());

    items_hash = HashInputs(items);

    yacl::parallel_for(0, items.size(), [&](int64_t begin, int64_t end) {
      for (int64_t idx = begin; idx < end; ++idx) {
        polynomial_eval_values[idx] = ::psi::mini_psi::EvalPolynomial(
            polynomial_coeff, absl::string_view(items_hash[idx]), prime256_str);

        std::array<uint8_t, kKeySize> ideal_permutation;
        // Ideal Permutation
        aes_ecb->Decrypt(absl::MakeSpan(reinterpret_cast<uint8_t*>(
                                            polynomial_eval_values[idx].data()),
                                        polynomial_eval_values[idx].length()),
                         absl::MakeSpan(ideal_permutation));

        std::string masked(kKeySize, '\0');

        curve25519_donna(
            reinterpret_cast<unsigned char*>(masked.data()), private_key.data(),
            static_cast<const unsigned char*>(ideal_permutation.data()));

        yacl::crypto::Sha256Hash sha256;
        sha256.Update(items[idx].data());
        sha256.Update(masked.data());
        std::vector<uint8_t> mask_hash = sha256.CumulativeHash();
        masked_values[idx].resize(kFinalCompareBytes);
        std::memcpy(masked_values[idx].data(), mask_hash.data(),
                    kFinalCompareBytes);
      }
    });

    // use sort as shuffle
    std::sort(masked_values.begin(), masked_values.end());
  }

  void SendMaskedEvalValues(
    const std::shared_ptr<yacl::link::Context>& link_ctx) {
  size_t batch_count = 0;

  // 直接按批次大小处理 masked_values
  size_t total_size = masked_values.size();
  size_t batch_size = kEcdhPsiBatchSize;

  for (size_t start = 0; start < total_size; start += batch_size) {
    PsiDataBatch batch;

    // 计算当前批次的结束位置
    size_t end = std::min(start + batch_size, total_size);

    // 检查是否是最后一批
    batch.is_last_batch = (end == total_size);

    // 批次数据添加到 batch.flatten_bytes 中
    batch.flatten_bytes.reserve((end - start) * kFinalCompareBytes);
    for (size_t i = start; i < end; i++) {
      batch.flatten_bytes.append(masked_values[i]);
    }

    // 发送批次数据
    const auto tag = fmt::format("MINI-PSI:X^A:{}", batch_count);
    link_ctx->SendAsyncThrottled(link_ctx->NextRank(), batch.Serialize(), tag);

    if (batch.is_last_batch) {
      SPDLOG_INFO("Last batch triggered, batch_count={}", batch_count);
      break;
    }
    batch_count++;
  }
  }


  // key
  std::array<uint8_t, kKeySize> private_key;
  std::array<uint8_t, kKeySize> public_key;

  // next prime over 2^256
  std::string prime256_str;

  // hash of items
  std::vector<std::string> items_hash;

  // polynomial_coeff
  std::vector<std::string> polynomial_coeff;

  std::vector<std::string> polynomial_eval_values;
  std::vector<std::string> masked_values;

  // use aes-128-ecb as Ideal Permutation
  std::shared_ptr<yacl::crypto::SymmetricCrypto> aes_ecb;
};

struct MiniPsiRecvCtx {
  MiniPsiRecvCtx() {
    prime256_str = absl::HexStringToBytes(kPrimeOver256bHexStr);
  }

  void GenerateSeeds(size_t data_size) {
    seeds.resize(data_size);
    seeds_point.resize(data_size);

    yacl::parallel_for(0, data_size, [&](int64_t begin, int64_t end) {
      for (int64_t idx = begin; idx < end; ++idx) {
        yacl::crypto::Prg<uint64_t> prg(0, yacl::crypto::PRG_MODE::kAesEcb);
        prg.Fill(absl::MakeSpan(seeds[idx].data(), kKeySize));

        curve25519_donna_basepoint(
            static_cast<unsigned char*>(seeds_point[idx].data()),
            seeds[idx].data());
      }
    });
  }

  void InterpolatePolynomial(const std::vector<std::string>& items) {
    items_hash = HashInputs(items);

    std::vector<absl::string_view> poly_x(items_hash.size());
    std::vector<absl::string_view> poly_y(items_hash.size());
    std::vector<std::array<uint8_t, kKeySize>> poly_y_permutation(
        items_hash.size());

    for (size_t idx = 0; idx < items_hash.size(); idx++) {
      poly_x[idx] = absl::string_view(items_hash[idx]);

      // Ideal Permutation
      aes_ecb->Encrypt(absl::MakeSpan(seeds_point[idx]),
                       absl::MakeSpan(poly_y_permutation[idx]));

      poly_y[idx] = absl::string_view(
          reinterpret_cast<const char*>(poly_y_permutation[idx].data()),
          kKeySize);
    }

    // ToDo: now use newton Polynomial Interpolation, need optimize to fft
    //
    polynomial_coeff =
        ::psi::mini_psi::InterpolatePolynomial(poly_x, poly_y, prime256_str);
  }

  void SendPolynomialCoeff(
    const std::shared_ptr<yacl::link::Context>& link_ctx) {
  size_t batch_count = 0;

  // 获取总大小和每批次的大小
  size_t total_size = polynomial_coeff.size();
  size_t batch_size = kEcdhPsiBatchSize;

  for (size_t start = 0; start < total_size; start += batch_size) {
    PsiDataBatch batch;

    // 计算当前批次的结束位置
    size_t end = std::min(start + batch_size, total_size);

    // 判断是否为最后一批
    batch.is_last_batch = (end == total_size);

    // 预分配空间并将当前批次数据添加到 batch.flatten_bytes 中
    batch.flatten_bytes.reserve((end - start) * kHashSize);
    for (size_t i = start; i < end; i++) {
      batch.flatten_bytes.append(polynomial_coeff[i]);
    }

    // 发送当前批次
    const auto tag = fmt::format("MINI-PSI:X^A:{}", batch_count);
    link_ctx->SendAsyncThrottled(link_ctx->NextRank(), batch.Serialize(), tag);

    if (batch.is_last_batch) {
      SPDLOG_INFO("Last batch triggered, batch_count={}", batch_count);
      break;
    }
    batch_count++;
  }
  }


  void RecvMaskedEvalValues(
      const std::shared_ptr<yacl::link::Context>& link_ctx) {
    size_t batch_count = 0;

    yacl::link::RecvTimeoutGuard guard(link_ctx, kLinkRecvTimeout);
    while (true) {
      const auto tag = fmt::format("MINI-PSI:X^A^B:{}", batch_count);
      PsiDataBatch masked_eval_batch =
          PsiDataBatch::Deserialize(link_ctx->Recv(link_ctx->NextRank(), tag));
      // Fetch y^b.
      YACL_ENFORCE(
          masked_eval_batch.flatten_bytes.size() % kFinalCompareBytes == 0);
      size_t num_items =
          masked_eval_batch.flatten_bytes.size() / kFinalCompareBytes;

      if (num_items > 0) {
        absl::string_view flatten_bytes = masked_eval_batch.flatten_bytes;

        for (size_t i = 0; i < num_items; ++i) {
          peer_masked_values.emplace(
              flatten_bytes.substr(i * kFinalCompareBytes, kFinalCompareBytes));
        }
      }
      if (masked_eval_batch.is_last_batch) {
        break;
      }
      batch_count++;
    }
  }

  void MaskPeerPublicKey(const std::vector<std::string>& items) {
    masked_values.resize(seeds.size());

    yacl::parallel_for(0, seeds.size(), [&](int64_t begin, int64_t end) {
      for (int64_t idx = begin; idx < end; ++idx) {
        std::string masked(kKeySize, '\0');
        curve25519_donna(reinterpret_cast<unsigned char*>(masked.data()),
                         seeds[idx].data(), peer_public_key.data());

        yacl::crypto::Sha256Hash sha256;
        sha256.Update(items[idx].data());
        sha256.Update(masked.data());
        std::vector<uint8_t> mask_hash = sha256.CumulativeHash();
        masked_values[idx].resize(kFinalCompareBytes);
        std::memcpy(masked_values[idx].data(), mask_hash.data(),
                    kFinalCompareBytes);
      }
    });
  }

  std::vector<std::string> GetIntersection(
      const std::vector<std::string>& items) {
    std::vector<std::string> ret;

    for (uint32_t index = 0; index < masked_values.size(); index++) {
      if (peer_masked_values.find(masked_values[index]) !=
          peer_masked_values.end()) {
        ret.push_back(items[index]);
      }
    }

    return ret;
  }

  std::vector<std::array<uint8_t, kKeySize>> seeds;
  std::vector<std::array<uint8_t, kKeySize>> seeds_point;

  // peer's public key
  std::array<uint8_t, kKeySize> peer_public_key;

  // next prime over 2^256
  std::string prime256_str;

  // hash of items
  std::vector<std::string> items_hash;

  // polynomial_coeff
  std::vector<std::string> polynomial_coeff;

  // dual mask value
  std::vector<std::string> masked_values;
  // peer's dual mask value
  std::unordered_set<std::string> peer_masked_values;

  // use aes-128-ecb as Ideal Permutation
  std::shared_ptr<yacl::crypto::SymmetricCrypto> aes_ecb;
};



// #define DEBUG_OUT

void MiniPsiSend(const std::shared_ptr<yacl::link::Context>& link_ctx,
                 const std::vector<std::string>& items) {
  MiniPsiSendCtx send_ctx;

  //
  // TODO: whether use zk to prove sender's public_key
  //    https://github.com/osu-crypto/MiniPSI/blob/master/libPSI/MiniPSI/MiniSender.cpp#L601
  //    MiniPSI code use zk prove public_key (discrete logarithm)
  //    in the origin paper no use zk
  //
  link_ctx->SendAsyncThrottled(
      link_ctx->NextRank(),
      yacl::Buffer(send_ctx.public_key.data(), send_ctx.public_key.size()),
      "MINI-PSI:X^A");

  // receive Polynomial Coefficient
  send_ctx.RecvPolynomialCoeff(link_ctx);

  std::future<void> f_eval =
      std::async([&] { send_ctx.EvalPolynomial(items); });

  f_eval.get();

  // send Polynomial evaluation and mask value to receiver
  send_ctx.SendMaskedEvalValues(link_ctx);
}

std::vector<std::string> MiniPsiRecv(
    const std::shared_ptr<yacl::link::Context>& link_ctx,
    const std::vector<std::string>& items) {
  MiniPsiRecvCtx recv_ctx;

  std::future<void> f_get_pubkey = std::async([&] {
    // receive sender's public key
    yacl::Buffer buf =
        link_ctx->Recv(link_ctx->NextRank(), fmt::format("MINI-PSI:X^A"));
    std::memcpy(recv_ctx.peer_public_key.data(), buf.data(), buf.size());

    uint128_t aes_key = yacl::crypto::Blake3_128(recv_ctx.peer_public_key);
    recv_ctx.aes_ecb = std::make_shared<yacl::crypto::SymmetricCrypto>(
        yacl::crypto::SymmetricCrypto::CryptoType::AES128_ECB, aes_key, 0);
  });

  std::future<void> f_gen_seeds = std::async([&] {
    // generate seed
    recv_ctx.GenerateSeeds(items.size());
  });
  f_get_pubkey.get();
  f_gen_seeds.get();

  std::future<void> f_interpolate =
      std::async([&] { recv_ctx.InterpolatePolynomial(items); });

  f_interpolate.get();

  // send polynomial coefficient to sender
  recv_ctx.SendPolynomialCoeff(link_ctx);

  std::future<void> f_mask_peer =
      std::async([&] { return recv_ctx.MaskPeerPublicKey(items); });

  f_mask_peer.get();

  // get sender's masked value
  recv_ctx.RecvMaskedEvalValues(link_ctx);

  // get intersection
  return recv_ctx.GetIntersection(items);
}

