

#include <cstddef>
#include <iostream>

#include "gtest/gtest.h"

#include "yacl/crypto/rand/rand.h"
#include "yacl/math/f2k/f2k.h"

uint128_t Evaluate(const std::vector<uint128_t>& coeffs, uint128_t x) {
  uint128_t y = coeffs.back();
  for (auto it = std::next(coeffs.rbegin()); it != coeffs.rend(); ++it) {
    y = yacl::GfMul128(y, x) ^ *it;
  }
  return y;
}

std::vector<uint128_t> Interpolate(const std::vector<uint128_t>& xs,
                                   const std::vector<uint128_t>& ys) {
  YACL_ENFORCE(xs.size() == ys.size());
  auto size = xs.size();
  auto poly = std::vector<uint128_t>(size + 1, 0);

  // Compute poly = (x - x0)(x - x1) ... (x - xn)
  poly[0] = 1;
  for (size_t j = 0; j < size; ++j) {
    uint128_t sum = 0;
    for (size_t k = 0; k <= j + 1; ++k) {
      sum = std::exchange(poly[k], yacl::GfMul128(poly[k], xs[j]) ^ sum);
    }
  }

  auto coeffs = std::vector<uint128_t>(size, 0);  // result

  for (size_t i = 0; i < size; ++i) {
    auto subpoly = std::vector<uint128_t>(size, 0);
    uint128_t xi = xs[i];
    subpoly[size - 1] = 1;
    for (int32_t k = size - 2; k >= 0; --k) {
      subpoly[k] = poly[k + 1] ^ yacl::GfMul128(subpoly[k + 1], xi);
    }

    auto prod = yacl::GfMul128(ys[i], yacl::GfInv128(Evaluate(subpoly, xi)));
    // update coeff
    for (size_t k = 0; k < size; ++k) {
      coeffs[k] = coeffs[k] ^ yacl::GfMul128(subpoly[k], prod);
    }
  }

  return coeffs;
}

int main() {
  size_t size = 1 << 10;
  auto xs = yacl::crypto::RandVec<uint128_t>(size);
  auto ys = yacl::crypto::RandVec<uint128_t>(size);
  auto start_time = std::chrono::high_resolution_clock::now();
  auto ceof = Interpolate(xs, ys);

  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  ;
  for (size_t i = 0; i < size; ++i) {
    // std::cout<<i<<std::endl;
    EXPECT_EQ(ys[i], Evaluate(ceof, xs[i]));
  }
}