
#include <cstddef>
#include <iostream>
#include <memory>
#include <vector>

#include "yacl/base/int128.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/link/link.h"
#include "yacl/utils/parallel.h"


int main(){
    auto ec = yacl::crypto::EcGroupFactory::Instance().Create(/* curve name */ "FourQ");

    yacl::crypto::MPInt sk;
    // Generate random key
    yacl::crypto::MPInt::RandomLtN(ec->GetOrder(), &sk);
    auto start = std::chrono::high_resolution_clock::now();
    for(size_t i = 0;i<10000;i++){
    // 需要测量的代码
    auto G1 = ec->MulBase(sk);
    auto affG1 = ec->GetAffinePoint(G1);
    }
    // 结束时间点
    auto end = std::chrono::high_resolution_clock::now();
    // 计算经过的时间，单位是微秒
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    std::cout << "scalar mul execution time: " << duration.count() << " microseconds"<<std::endl;
    return 0;

}