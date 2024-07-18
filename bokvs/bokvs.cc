
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>
#include "examples/okvs/galois128.h"
#include "yacl/base/int128.h"
#include "examples/bokvs/bokvs.h"
#include "yacl/utils/parallel.h"

using namespace std;

Row Ro(uint128_t key, uint128_t r, size_t n) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    std::vector<uint8_t> key_bytes(16);
    for (int i = 0; i < 16; ++i) {
        key_bytes[15 - i] = static_cast<uint8_t>(key >> (i * 8));
    }
    blake3_hasher_update(&hasher, key_bytes.data(), key_bytes.size());
    std::vector<uint8_t> result((n + 7) / 8);  
    blake3_hasher_finalize(&hasher, result.data(), result.size());
    uint128_t hash_value = BytesToUint128(result.data());
    uint128_t h1 = hash_value % r;
    std::vector<uint128_t> h2;
    h2.reserve(n);
    for (size_t bit_index = 0; bit_index < n; ++bit_index) {
        size_t byte_index = bit_index / 8;
        size_t bit_offset = bit_index % 8;
        bool bit = ((result[byte_index] >> (7 - bit_offset)) & 1) != 0;
        auto bit_value = static_cast<uint128_t>(bit);
        h2.push_back(bit_value);
    }
    return {h1, h2};
}

std::vector<uint128_t> OKVSBK::Encode(std::vector<uint128_t> keys,std::vector<uint128_t> values){
    auto n = this->n_;
    auto m = this->n_;
    auto w = this->w_;
    auto r = this->r_;
    std::vector<uint128_t> p(m);
    std::vector<uint128_t> piv(n);
    std::vector<bool> flags(n);
    std::vector<Row> rows(n);
    yacl::parallel_for(0, this->n_, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
          rows[idx] = Ro(keys[idx], r, w);
        }
    });
    for(size_t i = 0; i < n; i++){
		for(size_t j = 0; j < w; j++ ){
            if(rows[i].h2[j]!=0){
				piv[i] = j + rows[i].h1;
                flags[i] = true;
				for(size_t k = i + 1; k < n; k++){
					if(rows[k].h1 > piv[i]){
						break;
					}
					size_t posk = piv[i] - rows[k].h1;
					size_t poskk = j - posk;
                    okvs::Galois128 t(rows[i].h2[j]);
					t = t.Inv();
					if(rows[k].h2[posk] != 0){
                            cout<<i<<"         "<<j<<"           "<<k<<endl;
							okvs::Galois128 tt = t*rows[k].h2[posk];
							size_t shiftnum = w - j + posk;
							for(size_t s = posk; s < shiftnum; s++ ){
								rows[k].h2[s] = rows[k].h2[s] ^ (tt*rows[i].h2[poskk+s]).get<uint128_t>(0);
							}
							values[k] = values[k] ^ (tt * values[i]).get<uint128_t>(0);
                    }
		        }
                break;
	        }   
        }
        if(!flags[i]){
            std::cout<<"this"<<std::endl;
			throw std::runtime_error("encode failed, " + std::to_string(i));
		}  
    }

	for(int i = n - 1; i >= 0; i--){
		uint128_t res = 0;
		for(size_t j = 0; j < w; j++){	
			if(rows[i].h2[j]!= 0 ){
				size_t index = j + rows[i].h1;
                okvs::Galois128 temp(rows[i].h2[j]);
				res = res ^ (temp*p[index]).get<uint128_t>(0);
			}
		}
		res = values[i]^res;
        okvs::Galois128 t(rows[i].h2[piv[i]-rows[i].h1]);
		t = t.Inv();
		res = (t*res).get<uint128_t>(0);
		p[piv[i]] = res;
	}
    return p;
}
