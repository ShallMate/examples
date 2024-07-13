#include <iostream>
#include <vector>
#include "yacl/math/mpint/mp_int.h"
#include "seal/seal.h"

using namespace std;
using namespace seal;
using namespace yacl::math;

void MPIntToUInt64Vector(const MPInt &value, vector<uint64_t> &out_vector) {
    size_t byte_len = (value.BitCount() + 7) / 8;
    vector<uint8_t> buffer(byte_len); // 确保缓冲区大小足够
    size_t written_bytes = value.ToMagBytes(buffer.data(), buffer.size());

    if (written_bytes != buffer.size()) {
        throw std::runtime_error("Error in writing bytes.");
    }

    uint64_t part1 = 0, part2 = 0, part3 = 0, part4 = 0;

    // 将字节数组转换为 uint64_t 数组
    for (size_t i = 0; i < 8; ++i) {
        if (i < written_bytes) part1 |= static_cast<uint64_t>(buffer[i]) << (8 * i);
        if (i + 8 < written_bytes) part2 |= static_cast<uint64_t>(buffer[i + 8]) << (8 * i);
        if (i + 16 < written_bytes) part3 |= static_cast<uint64_t>(buffer[i + 16]) << (8 * i);
        if (i + 24 < written_bytes) part4 |= static_cast<uint64_t>(buffer[i + 24]) << (8 * i);
    }
    out_vector.push_back(part1);
    out_vector.push_back(part2);
    out_vector.push_back(part3);
    out_vector.push_back(part4);
}

MPInt UInt64VectorToMPInt(const vector<uint64_t> &vector) {
    MPInt result;
    ::vector<uint8_t> buffer(32, 0);

    for (size_t i = 0; i < 8; ++i) {
        buffer[i] = static_cast<uint8_t>((vector[0] >> (8 * i)) & 0xFF);
        buffer[i + 8] = static_cast<uint8_t>((vector[1] >> (8 * i)) & 0xFF);
        buffer[i + 16] = static_cast<uint8_t>((vector[2] >> (8 * i)) & 0xFF);
        buffer[i + 24] = static_cast<uint8_t>((vector[3] >> (8 * i)) & 0xFF);
    }

    yacl::Buffer buf(buffer.data(), buffer.size());
    result.FromMagBytes(buf);
    return result;
}

MPInt ModAdd(const MPInt& a, const MPInt& b, const MPInt& p) {
    MPInt sum;
    MPInt::Add(a, b, &sum);
    return sum % p;
}

MPInt ModMul(const MPInt& a, const MPInt& b, const MPInt& p) {
    MPInt product;
    MPInt::Mul(a, b, &product);
    return product % p;
}

int main() {
    // 定义256位的大素数 p
    MPInt p("115792089237316195423570985008687907853269984665640564039457584007913129639937", 10);

    // 创建加密参数
    EncryptionParameters parms(scheme_type::bfv);

    // 设置多项式模数度
    parms.set_poly_modulus_degree(8192);

    // 设置系数模数
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(8192));

    // 设置一个适当大小的明文模数
    parms.set_plain_modulus(786433); // 一个大约为2^19的素数

    // 创建 SEALContext
    SEALContext context(parms);

    // 生成密钥
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    // 创建加密器、解密器、编码器
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    // 定义两个在 Fp 中的整数
    MPInt value1("12345678901234567890123456789012345678901234567890123456789012345678901234567890", 10);
    MPInt value2("98765432109876543210987654321098765432109876543210987654321098765432109876543210", 10);

    // 将 MPInt 转换为 uint64_t 数组
    vector<uint64_t> value1_vector, value2_vector;
    MPIntToUInt64Vector(value1, value1_vector);
    MPIntToUInt64Vector(value2, value2_vector);

    // 编码明文
    Plaintext plaintext1, plaintext2;
    batch_encoder.encode(value1_vector, plaintext1);
    batch_encoder.encode(value2_vector, plaintext2);

    // 加密明文
    Ciphertext ciphertext1, ciphertext2;
    encryptor.encrypt(plaintext1, ciphertext1);
    encryptor.encrypt(plaintext2, ciphertext2);

    // 执行加法运算并模 p
    Ciphertext encrypted_sum;
    Evaluator evaluator(context);
    evaluator.add(ciphertext1, ciphertext2, encrypted_sum);

    // 执行乘法运算并模 p
    Ciphertext encrypted_product;
    evaluator.multiply(ciphertext1, ciphertext2, encrypted_product);
    evaluator.relinearize_inplace(encrypted_product, relin_keys);

    // 解密结果
    Plaintext decrypted_sum, decrypted_product;
    decryptor.decrypt(encrypted_sum, decrypted_sum);
    decryptor.decrypt(encrypted_product, decrypted_product);

    // 解码结果
    vector<uint64_t> decrypted_sum_vector, decrypted_product_vector;
    batch_encoder.decode(decrypted_sum, decrypted_sum_vector);
    batch_encoder.decode(decrypted_product, decrypted_product_vector);

    // 转换解码后的结果
    MPInt sum_result = UInt64VectorToMPInt(decrypted_sum_vector) % p;
    MPInt product_result = UInt64VectorToMPInt(decrypted_product_vector) % p;

    // 明文计算
    MPInt expected_sum = ModAdd(value1, value2, p);
    MPInt expected_product = ModMul(value1, value2, p);

    // 输出结果
    cout << "Sum in Fp: " << sum_result.ToString() << endl;
    cout << "Expected Sum in Fp: " << expected_sum.ToString() << endl;
    cout << "Product in Fp: " << product_result.ToString() << endl;
    cout << "Expected Product in Fp: " << expected_product.ToString() << endl;

    // 测试部分
    bool sum_test = sum_result.ToString() == expected_sum.ToString();
    bool product_test = product_result.ToString() == expected_product.ToString();

    if (sum_test && product_test) {
        cout << "Test passed!" << endl;
    } else {
        cout << "Test failed!" << endl;
    }

    return 0;
}
