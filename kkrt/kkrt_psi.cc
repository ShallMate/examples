#include "examples/kkrt/kkrt_psi.h"

#include <cstdint>
#include <cstring>
#include <future>
#include <numeric>
#include <string>

#include "absl/strings/escaping.h"
#include "openssl/crypto.h"
#include "openssl/rand.h"
#include "spdlog/spdlog.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/crypto/tools/prg.h"
#include "yacl/kernel/algorithms/base_ot.h"
#include "yacl/kernel/algorithms/iknp_ote.h"
#include "yacl/kernel/algorithms/kkrt_ote.h"
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
    serialized_data.append(reinterpret_cast<const char*>(&item_num),
                           sizeof(item_num));

    // 序列化 flatten_bytes 的长度和内容
    uint32_t flatten_bytes_size = flatten_bytes.size();
    serialized_data.append(reinterpret_cast<const char*>(&flatten_bytes_size),
                           sizeof(flatten_bytes_size));
    serialized_data.append(flatten_bytes);

    // 序列化 is_last_batch
    serialized_data.append(reinterpret_cast<const char*>(&is_last_batch),
                           sizeof(is_last_batch));

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
    std::memcpy(&batch.item_num, serialized_data.data() + offset,
                sizeof(batch.item_num));
    offset += sizeof(batch.item_num);

    // 反序列化 flatten_bytes 的长度和内容
    uint32_t flatten_bytes_size;
    std::memcpy(&flatten_bytes_size, serialized_data.data() + offset,
                sizeof(flatten_bytes_size));
    offset += sizeof(flatten_bytes_size);

    batch.flatten_bytes = serialized_data.substr(offset, flatten_bytes_size);
    offset += flatten_bytes_size;

    // 反序列化 is_last_batch
    std::memcpy(&batch.is_last_batch, serialized_data.data() + offset,
                sizeof(batch.is_last_batch));

    return batch;
  }
};

// constexpr size_t kPsiDataBatchSize = 1 << 10;
constexpr size_t kPsiDataBatchSize = 1024;
constexpr size_t kStashSize = 0;
constexpr size_t kCuckooHashNum = 3;
constexpr size_t kStatSecParam = 40;
constexpr size_t kKkrtOtBatchSize = (65535 / 4 / 16 * 0.8);  // NOLINT

// send set size to peer
// get peer's item size
//
size_t ExchangeSetSize(const std::shared_ptr<yacl::link::Context>& link_ctx,
                       size_t items_size) {
  // 将 size_t 类型的 input_size 序列化为字节数组
  size_t input_size = items_size;
  std::vector<uint8_t> serialized_input_size(sizeof(size_t));
  std::memcpy(serialized_input_size.data(), &input_size, sizeof(size_t));

  // 发送字节数组
  link_ctx->SendAsyncThrottled(
      link_ctx->NextRank(),
      std::string(serialized_input_size.begin(), serialized_input_size.end()),
      fmt::format("KKRT:PSI:SELF_SIZE={}", items_size));

  // 接收字节数组
  auto received_buffer =
      link_ctx->Recv(link_ctx->NextRank(), fmt::format("KKRT:PSI:PEER_SIZE"));

  // 将接收到的字节数组反序列化为 size_t 类型
  size_t peer_size;
  std::memcpy(&peer_size, received_buffer.data(), sizeof(size_t));

  return peer_size;
}

//
// stat_sec_param = 40, data_size 2^40 encode size is 15
// data_size > 2^40, use encode size 16,
// hash collision probability will > 2^-40
inline uint64_t KkrtEncodeSize(uint64_t stat_sec_param, uint128_t self_size,
                               uint128_t peer_size) {
  uint64_t encode_size =
      (stat_sec_param + std::log2l(self_size * peer_size) + 7) / 8;
  return std::min(encode_size, static_cast<uint64_t>(sizeof(uint128_t)));
}

KkrtPsiOptions GetDefaultKkrtPsiOptions() {
  KkrtPsiOptions kkrt_psi_options;

  kkrt_psi_options.ot_batch_size = kKkrtOtBatchSize;
  kkrt_psi_options.psi_batch_size = kPsiDataBatchSize;

  kkrt_psi_options.stash_size = kStashSize;
  kkrt_psi_options.cuckoo_hash_num = kCuckooHashNum;
  kkrt_psi_options.stat_sec_param = kStatSecParam;

  return kkrt_psi_options;
}

// first use baseOT get 128 ots
// then, use iknpOtExtension get 512 ots
yacl::crypto::OtRecvStore GetKkrtOtSenderOptions(
    const std::shared_ptr<yacl::link::Context>& link_ctx, const size_t num_ot) {
  // use base ot get 128 ots
  auto base_ot = yacl::crypto::BaseOtSend(link_ctx, 128);
  auto choice = yacl::crypto::RandBits(num_ot);

  return yacl::crypto::IknpOtExtRecv(link_ctx, base_ot, choice, num_ot);
}

yacl::crypto::OtSendStore GetKkrtOtReceiverOptions(
    const std::shared_ptr<yacl::link::Context>& link_ctx, const size_t num_ot) {
  // use base ot get 128 ots
  size_t base_ot_num = 128;
  auto base_ot_choice = yacl::crypto::RandBits(base_ot_num);
  auto base_ot = yacl::crypto::BaseOtRecv(link_ctx, base_ot_choice, 128);

  return yacl::crypto::IknpOtExtSend(link_ctx, base_ot, num_ot);
}

void KkrtPsiSend(const std::shared_ptr<yacl::link::Context>& link_ctx,
                 const KkrtPsiOptions& kkrt_psi_options,  // with kkrt options
                 yacl::crypto::OtRecvStore& ot_recv,
                 const std::vector<uint128_t>& items_hash) {
  YACL_ENFORCE((kkrt_psi_options.cuckoo_hash_num == 3) &&
                   (kkrt_psi_options.stash_size == 0),
               "now only support cuckoo HashNum = 3 , stash size = 0");
  YACL_ENFORCE(ot_recv.Size() == 512,
               "now only support baseRecvOption block size 512");

  size_t self_size = items_hash.size();
  size_t peer_size = ExchangeSetSize(link_ctx, self_size);
  YACL_ENFORCE((peer_size > 0) && (self_size > 0),
               "item size need not zero, mine={}, peer={}", self_size,
               peer_size);

  uint64_t encode_size =
      KkrtEncodeSize(kkrt_psi_options.stat_sec_param, self_size,
                     peer_size);  // by byte

  yacl::CuckooIndex::Options option = yacl::CuckooIndex::SelectParams(
      peer_size, kkrt_psi_options.stash_size, kkrt_psi_options.cuckoo_hash_num);
  size_t num_bins = option.NumBins();

  yacl::crypto::KkrtOtExtSender sender;
  sender.Init(link_ctx, ot_recv, option.NumBins());
  sender.SetBatchSize(kKkrtOtBatchSize);
  uint64_t kkrtOtBatchSize = sender.GetBatchSize();

  std::atomic<uint64_t> recv_idx(0);
  auto f_recv_corrections = std::async([&]() {
    // while there are more corrections for be received
    size_t correction_batch_idx = 0;
    while (recv_idx < num_bins) {
      // compute the  size of the current step and the end index
      size_t current_step_size = std::min(kkrtOtBatchSize, num_bins - recv_idx);

      // receive the corrections.
      auto current_correction_buf = link_ctx->Recv(
          link_ctx->NextRank(),
          fmt::format("KKRT:PSI:ThrottleControlReceiver recv batch_count:{}",
                      correction_batch_idx));
      sender.SetCorrection(current_correction_buf, current_step_size);
      correction_batch_idx++;

      // notify the other thread that the corrections have arrived
      recv_idx.fetch_add(current_step_size, std::memory_order_release);
    }
  });

  // permute sender input data
  std::vector<size_t> input_permute;
  std::vector<size_t> input_permute_inv;
  input_permute.resize(self_size);
  input_permute_inv.resize(self_size);

  std::iota(input_permute.begin(), input_permute.end(), 0);

  yacl::crypto::Prg<uint128_t> prg(yacl::crypto::SecureRandSeed());
  uint64_t mt_seed;
  prg.Fill(
      absl::MakeSpan(reinterpret_cast<uint8_t*>(&mt_seed), sizeof(mt_seed)));
  std::mt19937 rng(mt_seed);
  std::shuffle(input_permute.begin(), input_permute.end(), rng);
  for (size_t i = 0; i < self_size; i++) {
    input_permute_inv[input_permute[i]] = i;
  }

  // hash bucketing
  yacl::Buffer encode_buf(self_size * kkrt_psi_options.cuckoo_hash_num *
                          encode_size);
  std::vector<std::array<uint64_t, kCuckooHashNum>> bin_indices;
  bin_indices.resize(self_size);

  for (size_t i = 0; i < self_size; ++i) {
    yacl::CuckooIndex::HashRoom itemHash(items_hash[i]);
    uint64_t bin_idx0 = itemHash.GetHash(0) % num_bins;
    uint64_t bin_idx1 = itemHash.GetHash(1) % num_bins;
    uint64_t bin_idx2 = itemHash.GetHash(2) % num_bins;

    bin_indices[i][0] = bin_idx0;
    // check collision
    uint8_t c01 = (bin_idx0 == bin_idx1) ? 1 : 0;
    bin_indices[i][1] = bin_idx1 | (c01 * static_cast<uint64_t>(-1));
    uint8_t c02 = (bin_idx0 == bin_idx2 || bin_idx1 == bin_idx2) ? 1 : 0;
    bin_indices[i][2] = bin_idx2 | (c02 * static_cast<uint64_t>(-1));
    if (c01 == 1) {
      uint8_t* encode_pos =
          encode_buf.data<uint8_t>() +
          (input_permute_inv[i] * kkrt_psi_options.cuckoo_hash_num + 1) *
              encode_size;
      prg.Fill(absl::MakeSpan(encode_pos, encode_size));
    }
    if (c02 == 1) {
      uint8_t* encode_pos =
          encode_buf.data<uint8_t>() +
          (input_permute_inv[i] * kkrt_psi_options.cuckoo_hash_num + 2) *
              encode_size;
      prg.Fill(absl::MakeSpan(encode_pos, encode_size));
    }
  }

  uint64_t t = 0;
  uint64_t r = 0;
  // while not all the corrections have been received, try to encode any that
  // we can
  // TODO(shuyan.ycf): this implementation wastes cpus if the networking is
  // slow (Due to spin logics). Better use synchronization primitives.
  while (r != num_bins) {
    // process things in steps
    for (uint64_t j = 0; j < kkrtOtBatchSize; ++j) {
      // lets check a random item to see if it can be encoded. If so,
      // we will write this item's encodings in the myMaskBuff at position i.
      auto input_idx = input_permute[t];

      // for each hash function, try to encode the item.
      for (uint64_t h = 0; h < kkrt_psi_options.cuckoo_hash_num; ++h) {
        uint64_t b_idx = bin_indices[input_idx][h];

        // if the bin index is less than r, then we have received
        // the correction and can encode it
        if (b_idx < r) {
          // write the encoding into encode_buf at position  t, h
          uint8_t* encoding =
              encode_buf.data<uint8_t>() +
              (t * kkrt_psi_options.cuckoo_hash_num + h) * encode_size;
          sender.Encode(b_idx, items_hash[input_idx], encoding, encode_size);

          // make this location as already been encoded
          bin_indices[input_idx][h] = -1;
        }
      }

      // wrap around the input looking for items that we can encode
      t = (t + 1) % self_size;
    }

    // after stepSize attempts to encode items, lets see if more
    // corrections have arrived.
    r = recv_idx.load(std::memory_order_acquire);
  }

  // Join receiving thread and throw exceptions if any thing is wrong.
  f_recv_corrections.get();

  // encoding buffer
  for (size_t i = 0; i < self_size;) {
    size_t curr_step_item_num =
        std::min(kkrt_psi_options.psi_batch_size, self_size - i);
    size_t curr_step_encode_num =
        curr_step_item_num * kkrt_psi_options.cuckoo_hash_num;

    PsiDataBatch batch;
    batch.flatten_bytes.resize(encode_size * curr_step_encode_num);
    uint8_t* encoding = encode_buf.data<uint8_t>() +
                        (i * kkrt_psi_options.cuckoo_hash_num) * encode_size;
    for (size_t j = 0; j < curr_step_item_num; ++j) {
      auto input_idx = input_permute[i + j];

      for (size_t k = 0; k < kkrt_psi_options.cuckoo_hash_num; k++) {
        uint64_t b_idx = bin_indices[input_idx][k];

        if (b_idx != static_cast<uint64_t>(-1)) {
          sender.Encode(b_idx, items_hash[input_idx], encoding, encode_size);
        }
        encoding += encode_size;
      }
    }

    batch.item_num = curr_step_item_num;
    batch.is_last_batch = false;

    encoding = encode_buf.data<uint8_t>() +
               (i * kkrt_psi_options.cuckoo_hash_num) * encode_size;
    memcpy(batch.flatten_bytes.data(), encoding,
           encode_size * curr_step_encode_num);

    i += curr_step_item_num;
    if (i == self_size) {
      batch.is_last_batch = true;
    }

    link_ctx->SendAsyncThrottled(
        link_ctx->NextRank(), batch.Serialize(),
        fmt::format("KKRT:PSI:SENDER OPRF:{}", curr_step_item_num));
  }

  const char* finish_str = "kkrt finish";

  link_ctx->SendAsyncThrottled(link_ctx->NextRank(), finish_str,
                               fmt::format("KKRT:PSI:Finished"));
}

std::vector<std::size_t> KkrtPsiRecv(
    const std::shared_ptr<yacl::link::Context>& link_ctx,
    const KkrtPsiOptions& kkrt_psi_options,  // with kkrt options
    yacl::crypto::OtSendStore& ot_send,
    const std::vector<uint128_t>& items_hash) {
  YACL_ENFORCE((kkrt_psi_options.cuckoo_hash_num == 3) &&
                   (kkrt_psi_options.stash_size == 0),
               "now only support cuckoo HashNum = 3 , stash size = 0");

  YACL_ENFORCE(ot_send.Size() == 512,
               "now only support yacl::OtSendStore block size 512");

  std::vector<std::size_t> ret_intersection;

  size_t self_size = items_hash.size();
  size_t peer_size = ExchangeSetSize(link_ctx, self_size);

  YACL_ENFORCE((peer_size > 0) && (!items_hash.empty()),
               "item size need not zero, mine={}, peer={}", self_size,
               peer_size);

  yacl::CuckooIndex::Options option = yacl::CuckooIndex::SelectParams(
      self_size, kkrt_psi_options.stash_size, kkrt_psi_options.cuckoo_hash_num);
  yacl::CuckooIndex cuckoo_index(option);
  cuckoo_index.Insert(absl::MakeSpan(items_hash));
  YACL_ENFORCE(cuckoo_index.stash().empty(), "stash size not 0");
  size_t kkrt_ot_num = cuckoo_index.bins().size();

  yacl::crypto::KkrtOtExtReceiver receiver;
  receiver.Init(link_ctx, ot_send, kkrt_ot_num);
  receiver.SetBatchSize(kkrt_psi_options.ot_batch_size);
  uint64_t kkrt_ot_batch_size = receiver.GetBatchSize();

  std::array<std::unordered_map<std::string, size_t>, kCuckooHashNum>
      oprf_encode_map;
  for (size_t i = 0; i < kCuckooHashNum; i++) {
    oprf_encode_map[i].reserve(kkrt_ot_num);
  }
  uint64_t encode_size =
      KkrtEncodeSize(kkrt_psi_options.stat_sec_param, self_size,
                     peer_size);  // by byte

  // encoding prf & send correction
  auto ck_bins = cuckoo_index.bins();
  std::string encode_str(encode_size, '\0');
  const size_t ot_num_batch =
      (kkrt_ot_num + kkrt_ot_batch_size - 1) / kkrt_ot_batch_size;
  for (size_t batch_idx = 0; batch_idx < ot_num_batch; ++batch_idx) {
    const size_t num_this_batch = std::min<size_t>(
        kkrt_ot_num - batch_idx * kkrt_ot_batch_size, kkrt_ot_batch_size);

    size_t batch_start = batch_idx * kkrt_ot_batch_size;
    for (size_t i = 0; i < num_this_batch; ++i) {
      size_t current_idx = batch_start + i;
      if (ck_bins[current_idx].IsEmpty()) {
        receiver.ZeroEncode(current_idx);
      } else {
        uint128_t input_item = items_hash[ck_bins[current_idx].InputIdx()];
        receiver.Encode(
            current_idx, input_item,
            absl::Span<uint8_t>(reinterpret_cast<uint8_t*>(encode_str.data()),
                                encode_size));

        uint8_t min_hash_idx = cuckoo_index.MinCollidingHashIdx(current_idx);
        oprf_encode_map[min_hash_idx].emplace(encode_str,
                                              ck_bins[current_idx].InputIdx());
      }
    }
    auto send_buf = receiver.ShiftCorrection(num_this_batch);
    link_ctx->SendAsyncThrottled(
        link_ctx->NextRank(), send_buf,
        fmt::format("KKRT_PSI:sendCorrection:{}", batch_idx));
  }

  size_t batch_count = 0;
  while (true) {
    // Receive sender prf encode.
    PsiDataBatch batch = PsiDataBatch::Deserialize(link_ctx->Recv(
        link_ctx->NextRank(),
        fmt::format("KKRT:PSI:RECEIVE:Receive sender prf encode:{}",
                    batch_count)));
    batch_count++;

    const bool is_last_batch = batch.is_last_batch;

    size_t curr_step_item_num = batch.item_num;
    size_t curr_step_encode_num =
        curr_step_item_num * kkrt_psi_options.cuckoo_hash_num;
    YACL_ENFORCE_EQ(batch.flatten_bytes.size(),
                    (curr_step_encode_num * encode_size));

    for (size_t i = 0; i < curr_step_item_num; ++i) {
      for (size_t j = 0; j < kkrt_psi_options.cuckoo_hash_num; ++j) {
        std::string encode_sub_str = batch.flatten_bytes.substr(
            (i * kkrt_psi_options.cuckoo_hash_num + j) * encode_size,
            encode_size);

        auto it = oprf_encode_map[j].find(encode_sub_str);
        if (it != oprf_encode_map[j].end()) {
          ret_intersection.emplace_back(it->second);
        }
      }
    }

    if (is_last_batch) {
      break;
    }
  }

  link_ctx->Recv(link_ctx->NextRank(),
                 fmt::format("KKRT:PSI:Wait Sender Finished"));

  return ret_intersection;
}
