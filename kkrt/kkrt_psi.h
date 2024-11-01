#pragma once

#include <algorithm>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "yacl/kernel/type/ot_store.h"
#include "yacl/link/link.h"

struct KkrtPsiOptions {
  // batch size the receiver send corrections
  size_t ot_batch_size = 128;

  // batch size the sender used to send oprf encode
  size_t psi_batch_size = 128;

  // cuckoo hash parameter
  // now use stashless setting
  // stash_size = 0  cuckoo_hash_num =3
  // use stat_sec_param = 40
  size_t cuckoo_hash_num = 3;
  size_t stash_size = 0;
  size_t stat_sec_param = 40;
};

yacl::crypto::OtRecvStore GetKkrtOtSenderOptions(
    const std::shared_ptr<yacl::link::Context>& link_ctx, size_t num_ot);

yacl::crypto::OtSendStore GetKkrtOtReceiverOptions(
    const std::shared_ptr<yacl::link::Context>& link_ctx, size_t num_ot);

KkrtPsiOptions GetDefaultKkrtPsiOptions();

//
// sender and receiver psi input data shoud be prepocessed using hash algorithm.
// like sha256 or blake2/blake3 hash algorithm or aes_ecb(key, x)^x
//
void KkrtPsiSend(const std::shared_ptr<yacl::link::Context>& link_ctx,
                 const KkrtPsiOptions& kkrt_psi_options,
                 yacl::crypto::OtRecvStore& ot_recv,
                 const std::vector<uint128_t>& items_hash);

std::vector<std::size_t> KkrtPsiRecv(
    const std::shared_ptr<yacl::link::Context>& link_ctx,
    const KkrtPsiOptions& kkrt_psi_options, yacl::crypto::OtSendStore& ot_send,
    const std::vector<uint128_t>& items_hash);

// inline functions
inline void KkrtPsiSend(const std::shared_ptr<yacl::link::Context>& link_ctx,
                        const std::vector<uint128_t>& items_hash) {
  KkrtPsiOptions kkrt_psi_options = GetDefaultKkrtPsiOptions();

  // 创建 OtRecvStore 实例，而非使用智能指针
  yacl::crypto::OtRecvStore ot_recv = GetKkrtOtSenderOptions(link_ctx, 512);

  // 调用带选项的 KkrtPsiSend
  return KkrtPsiSend(link_ctx, kkrt_psi_options, ot_recv, items_hash);
}

inline std::vector<std::size_t> KkrtPsiRecv(
    const std::shared_ptr<yacl::link::Context>& link_ctx,
    const std::vector<uint128_t>& items_hash) {
  KkrtPsiOptions kkrt_psi_options = GetDefaultKkrtPsiOptions();

  // 创建 OtSendStore 实例，而非使用智能指针
  yacl::crypto::OtSendStore ot_send = GetKkrtOtReceiverOptions(link_ctx, 512);

  // 调用带选项的 KkrtPsiRecv
  return KkrtPsiRecv(link_ctx, kkrt_psi_options, ot_send, items_hash);
}
