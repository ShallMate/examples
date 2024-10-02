#include <iostream>
#include <vector>

#include "seal/seal.h"

using namespace std;
using namespace seal;

int main() {
  EncryptionParameters parms(scheme_type::bfv);

  // 自动选择多项式模数度（8192 或 16384 根据需求调整）
  size_t poly_modulus_degree = 1 << 15;  // 可根据需要调整为 4096, 8192, 16384
  parms.set_poly_modulus_degree(poly_modulus_degree);

  // 使用 SEAL 的推荐系数模数
  parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

  // 设置一个适合批处理的明文模数
  parms.set_plain_modulus(65537);  // 可以尝试更小的模数，如 257，视具体需求

  // 创建 SEALContext
  SEALContext context(parms);

  // 输出参数的安全等级和相关信息
  auto context_data = context.key_context_data();
  cout << "Maximal bit count for coeff_modulus: "
       << context_data->total_coeff_modulus_bit_count() << endl;
  cout << "Plain modulus: " << parms.plain_modulus().value() << endl;

  // 检查参数是否有效
  if (!context.parameters_set()) {
    cout << "Encryption parameters are not valid!" << endl;
    return 1;
  }

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
  Evaluator evaluator(context);

  // 获取batch_size
  size_t batch_size = batch_encoder.slot_count();
  cout << batch_size << endl;

  // 定义两个 0,1 向量
  vector<uint64_t> value1_vector(batch_size, 0);  // 初始为全0
  vector<uint64_t> value2_vector(batch_size, 0);  // 初始为全0

  // 设置向量的一些值为1 (这将模拟0和1的二进制向量)
  value1_vector[0] = 1;
  value1_vector[1] = 0;
  value1_vector[2] = 1;
  value1_vector[3] = 1;

  value2_vector[0] = 0;
  value2_vector[1] = 1;
  value2_vector[2] = 1;
  value2_vector[3] = 0;

  // 编码明文
  Plaintext plaintext1, plaintext2;
  batch_encoder.encode(value1_vector, plaintext1);
  batch_encoder.encode(value2_vector, plaintext2);

  // 加密明文
  Ciphertext ciphertext1, ciphertext2;
  encryptor.encrypt(plaintext1, ciphertext1);
  encryptor.encrypt(plaintext2, ciphertext2);

  // 执行按位加法运算 (XOR-like behavior in binary)
  Ciphertext encrypted_sum;
  evaluator.add(ciphertext1, ciphertext2, encrypted_sum);

  // 执行按位乘法运算 (AND-like behavior in binary)
  Ciphertext encrypted_product;
  evaluator.multiply(ciphertext1, ciphertext2, encrypted_product);
  evaluator.relinearize_inplace(encrypted_product, relin_keys);  // 重线性化

  // 解密结果
  Plaintext decrypted_sum, decrypted_product;
  decryptor.decrypt(encrypted_sum, decrypted_sum);
  decryptor.decrypt(encrypted_product, decrypted_product);

  // 解码结果
  vector<uint64_t> decrypted_sum_vector, decrypted_product_vector;
  batch_encoder.decode(decrypted_sum, decrypted_sum_vector);
  batch_encoder.decode(decrypted_product, decrypted_product_vector);

  // 输出按位加法和乘法的结果
  cout << "Sum (XOR) result: ";
  for (size_t i = 0; i < 4; i++) {
    cout << decrypted_sum_vector[i] << " ";
  }
  cout << endl;

  cout << "Product (AND) result: ";
  for (size_t i = 0; i < 4; i++) {
    cout << decrypted_product_vector[i] << " ";
  }
  cout << endl;

  return 0;
}
