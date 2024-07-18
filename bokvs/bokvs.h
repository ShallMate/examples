// Copyright 2019 Ant Group Co., Ltd.
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

#include <cmath>
#include <cstddef>
#include <vector>
#include <cstring>
#include "yacl/base/int128.h"
#include "c/blake3.h"

struct Row {
    uint128_t h1;
    std::vector<uint128_t> h2;
};

inline uint128_t BytesToUint128(const uint8_t* bytes) {
    uint128_t value = 0;
    for (int i = 0; i < 16; ++i) {
        value = (value << 8) | bytes[i];
    }
    return value;
}



class OKVSBK {
public:
    OKVSBK(size_t n, size_t w, double e) : n_(n), w_(w), e_(e) {
        m_ = std::ceil(n * e);
        r_ = m_-w;
    }

    size_t getN() const {
        return n_;
    }

    size_t getM() const {
        return m_;
    }

    size_t getW() const {
        return w_;
    }

    size_t getR() const {
        return r_;
    }

    double getE() const {
        return e_;
    }

    std::vector<uint128_t> Encode(std::vector<uint128_t> keys,std::vector<uint128_t> values);
    std::vector<uint128_t> Decode(std::vector<uint128_t> keys,std::vector<uint128_t> p);

private:
    size_t n_; // okvs存储的k-v长度
    size_t m_; // okvs的实际长度
    size_t w_; // 随机块的长度
    size_t r_; // hashrange
    double e_; 
};

