#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <sstream>
#include <stdexcept>

/**
 * @brief Тест шифрования и дешифрования с корректными аргументами
 * Ошибок и исключений не ожидается
 */
TEST(CryptoGuardCtx, Crypto_CorrectArgs) {

    std::string input = "ABCDEFGHIGKLMNOPQRSTUVWXYZ0123456789-+|'!@#$%^&*()[]{}";
    std::string_view password = "key_to_the_heart";

    std::stringstream inStream(input);
    std::stringstream encryptStream;
    std::stringstream decryptStream;

    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_NO_THROW(ctx.EncryptFile(inStream, encryptStream, password));
    ASSERT_NO_THROW(ctx.DecryptFile(encryptStream, decryptStream, password));
    EXPECT_EQ(input, decryptStream.str());
}

/**
 * @brief Тест шифрования: входной поток с флагами ошибки
 * Ожидается исключение
 */
TEST(CryptoGuardCtx, Encrypt_InvalidInputStream) {

    std::stringstream inStream, outStream;
    std::string_view password = "key_to_the_heart";

    inStream.setstate(std::ios::failbit);

    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_THROW(ctx.EncryptFile(inStream, outStream, password), std::runtime_error);
}

/**
 * @brief Тест шифрования: выходной поток с флагами ошибки
 * Ожидается исключение
 */
TEST(CryptoGuardCtx, Encrypt_InvalidOutputStream) {

    std::string input = "ABCDEFGHIGKLMNOPQRSTUVWXYZ0123456789-+|'!@#$%^&*()[]{}";
    std::string_view password = "key_to_the_heart";

    std::stringstream inStream(input);
    std::stringstream outStream;

    outStream.setstate(std::ios::failbit);

    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_THROW(ctx.EncryptFile(inStream, outStream, password), std::runtime_error);
}

/**
 * @brief Тест шифрования: пустой пароль
 * Ожидается исключение
 */
TEST(CryptoGuardCtx, Encrypt_EmptyPassword) {

    std::string input = "ABCDEFGHIGKLMNOPQRSTUVWXYZ0123456789-+|'!@#$%^&*()[]{}";
    std::string_view password;

    std::stringstream inStream(input);
    std::stringstream outStream;

    outStream.setstate(std::ios::failbit);

    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_THROW(ctx.EncryptFile(inStream, outStream, password), std::runtime_error);
}

/**
 * @brief Тест шифрования: Длина данных меньше размера блока шифрования 16
 * Проверяется, что в конце шифрования была вызвана функция EVP_CipherFinal_ex().
 * Ошибок и исключений не ожидается.
 */
TEST(CryptoGuardCtx, Encrypt_InputLenLess16) {

    std::string input = "ABCDEF";
    std::string_view password = "key_to_the_heart";

    std::stringstream inStream(input);
    std::stringstream encryptStream;
    std::stringstream decryptStream;

    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_NO_THROW(ctx.EncryptFile(inStream, encryptStream, password));
    EXPECT_GE(encryptStream.str().length(), input.length());
}

/**
 * @brief Тест дешифрования: входной поток с флагами ошибки
 * Ожидается исключение
 */
TEST(CryptoGuardCtx, Decrypt_InvalidInputStream) {

    std::stringstream inStream, outStream;
    std::string_view password = "key_to_the_heart";

    inStream.setstate(std::ios::failbit);

    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_THROW(ctx.DecryptFile(inStream, outStream, password), std::runtime_error);
}

/**
 * @brief Тест дешифрования: выходной поток с флагами ошибки
 * Ожидается исключение
 */
TEST(CryptoGuardCtx, Decrypt_InvalidOutputStream) {

    std::string input = "ABCDEFGHIGKLMNOPQRSTUVWXYZ0123456789-+|'!@#$%^&*()[]{}";
    std::string_view password = "key_to_the_heart";

    std::stringstream inStream(input);
    std::stringstream outStream;

    outStream.setstate(std::ios::failbit);

    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_THROW(ctx.DecryptFile(inStream, outStream, password), std::runtime_error);
}

/**
 * @brief Тест дешифрования: пустой пароль
 * Ожидается исключение
 */
TEST(CryptoGuardCtx, Decrypt_EmptyPassword) {

    std::string input = "ABCDEFGHIGKLMNOPQRSTUVWXYZ0123456789-+|'!@#$%^&*()[]{}";
    std::string_view password;

    std::stringstream inStream(input);
    std::stringstream outStream;

    outStream.setstate(std::ios::failbit);

    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_THROW(ctx.DecryptFile(inStream, outStream, password), std::runtime_error);
}

/**
 * @brief Тест контрольной суммы: корректные входные данные
 *
 * Ошибок/исключений не ожидается
 */
TEST(CryptoGuardCtx, Checksum_Correct) {

    std::string input = "ABCDEFGHIGKLMNOPQRSTUVWXYZ0123456789-+|'!@#$%^&*()[]{}";
    std::string expect_hash = "3b0040cc6b156591e4de5dc3259dd735ba5585533495de359ddfe007fb7a1574";
    std::string actual_hash;

    std::stringstream inStream(input);

    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_NO_THROW(actual_hash = ctx.CalculateChecksum(inStream));
    EXPECT_EQ(actual_hash, expect_hash);
}

/**
 * @brief Тест контрольной суммы: Размер входных данных < 16 байт
 *
 * Проверяется наличие вызова EVP_DigestFinal_ex()
 */
TEST(CryptoGuardCtx, Checksum_LenLess16) {

    std::string input = "ABC";
    std::string expect_hash = "b5d4045c3f466fa91fe2cc6abe79232a1a57cdf104f7a26e716e0a1e2789df78";
    std::string actual_hash;

    std::stringstream inStream(input);

    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_NO_THROW(actual_hash = ctx.CalculateChecksum(inStream));
    EXPECT_EQ(actual_hash, expect_hash);
}

/**
 * @brief Тест контрольной суммы: входной поток с флагами ошибки
 *
 * Ожидается исключение
 */
TEST(CryptoGuardCtx, Checksum_InvalidInput) {

    std::stringstream inStream;
    inStream.setstate(std::ios::failbit);

    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_THROW(ctx.CalculateChecksum(inStream), std::runtime_error);
}
