// Copyright 2024 Guowei LING.
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

#pragma once

#include "examples/opprf/okvs/baxos.h"

#include "yacl/link/test_util.h"

namespace opprf {

std::vector<uint128_t> OPPRFRecv(
    const std::shared_ptr<yacl::link::Context>& ctx,
    std::vector<uint128_t>& elem_hashes, okvs::Baxos sendbaxos,
    okvs::Baxos recvbaxos);

void OPPRFSend(const std::shared_ptr<yacl::link::Context>& ctx,
               std::vector<uint128_t>& elem_hashes,
               std::vector<uint128_t>& elem_hashes1, okvs::Baxos sendbaxos,
               okvs::Baxos recvbaxos);

}  // namespace opprf
