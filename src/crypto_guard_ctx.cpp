#include "crypto_guard_ctx.h"
#include <array>
#include <format>
#include <iomanip>
#include <ios>
#include <iostream>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>

#define AES_BLOCK_SIZE 16

namespace CryptoGuard {

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

class CryptoGuardCtx::Impl {

public:
    Impl() { OpenSSL_add_all_algorithms(); }
    ~Impl() { EVP_cleanup(); }

    /**
     * @brief Шифрование данных
     *
     * @param inStream  Поток входных данных, которые нужно зашифровать
     * @param outStream Поток выходных данных, куда будут записаны данные в зашифрованном виде
     * @param password  Пароль для шифрования
     */
    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        doCrypt(inStream, outStream, password, true);
    }

    /**
     * @brief Расшифровка данных
     *
     * @param inStream  Поток входных зашифрованных данных
     * @param outStream Поток выходных данных, куда будут записаны данные в расшифрованном виде
     * @param password  Пароль для расшифровки
     */
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        doCrypt(inStream, outStream, password, false);
    }

    /**
     * @brief Вычисление контрольной суммы
     *
     * @param inStream Поток входных данных
     * @return Контрольную сумму в hex виде
     *
     * Для вычисления контрольной суммы используется алгоритм SHA256
     */
    std::string CalculateChecksum(std::iostream &inStream) {

        if (!inStream) {
            throw std::runtime_error{"invalid input stream"};
        }

        std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *ctx) { EVP_MD_CTX_free(ctx); })> ctx(EVP_MD_CTX_new());

        const EVP_MD *md = EVP_sha256();
        int err = EVP_DigestInit_ex(ctx.get(), md, nullptr);
        if (err != 1) {
            std::string errText = ERR_error_string(ERR_get_error(), nullptr);
            throw std::runtime_error{std::format("EVP_DigestInit_ex: {}", errText)};
        }

        unsigned char inBuffer[4096];
        while (inStream.read((char *)inBuffer, sizeof(inBuffer)) || inStream.gcount() > 0) {
            int bytesRead = inStream.gcount();
            err = EVP_DigestUpdate(ctx.get(), &inBuffer, bytesRead);
            if (err != 1) {
                std::string errText = ERR_error_string(ERR_get_error(), nullptr);
                throw std::runtime_error{std::format("EVP_DigestUpdate: {}", errText)};
            }
        }

        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int len = 0;
        err = EVP_DigestFinal_ex(ctx.get(), hash, &len);
        if (err != 1) {
            std::string errText = ERR_error_string(ERR_get_error(), nullptr);
            throw std::runtime_error{std::format("EVP_DigestFinal_ex: {}", errText)};
        }

        std::stringstream hexStream;
        hexStream << std::hex << std::setfill('0');
        for (size_t i = 0; i < len; i++) {
            hexStream << std::setw(2) << static_cast<int>(hash[i]);
        }

        return hexStream.str();
    }

private:
    /**
     * @brief Выполнение операции шифрования или дешифрования
     *
     * @param inStream  Поток входных данных
     * @param outStream Поток выходных данных
     * @param password  Пароль
     * @param isEncrypt Для шифрования TRUE, для дешифрования FALSE
     */
    void doCrypt(std::iostream &inStream, std::iostream &outStream, std::string_view password, bool isEncrypt) {
        if (!inStream) {
            throw std::runtime_error{"invalid input stream"};
        }
        if (!outStream) {
            throw std::runtime_error{"invalid output stream"};
        }

        std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })> ctx(
            EVP_CIPHER_CTX_new());

        auto params = CreateChiperParamsFromPassword(password, isEncrypt);
        int err =
            EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);
        if (err != 1) {
            char *errText = ERR_error_string(ERR_get_error(), nullptr);
            throw std::runtime_error{std::format("EVP_CipherInit_ex: {}", errText)};
        }

        unsigned char inBuffer[AES_BLOCK_SIZE];
        unsigned char outBuffer[AES_BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH];
        int bytesWrite = 0;
        while (inStream.read((char *)inBuffer, sizeof(inBuffer)) || inStream.gcount() > 0) {
            int bytesRead = inStream.gcount();
            err = EVP_CipherUpdate(ctx.get(), outBuffer, &bytesWrite, inBuffer, bytesRead);
            if (err != 1) {
                char *errText = ERR_error_string(ERR_get_error(), nullptr);
                throw std::runtime_error{std::format("EVP_CipherUpdate: {}", errText)};
            }
            if (bytesWrite > 0) {
                outStream.write((char *)outBuffer, bytesWrite);
            }
        }

        err = EVP_CipherFinal_ex(ctx.get(), (unsigned char *)&outBuffer, &bytesWrite);
        if (err != 1) {
            char *errText = ERR_error_string(ERR_get_error(), nullptr);
            throw std::runtime_error{std::format("EVP_CipherFinal_ex: {}", errText)};
        }
        if (bytesWrite > 0) {
            outStream.write((char *)outBuffer, bytesWrite);
        }
    }

    /**
     * @brief Получение инициализированной структуры для шифрования/дешифрования
     *
     * @param password  Пароль (ключ шифрования/дешифрования)
     * @param isEncrypt Для шифрования TRUE, для дешифрования FALSE
     * @return Структуру с инициализированными полями
     */
    AesCipherParams CreateChiperParamsFromPassword(std::string_view password, bool isEncrypt) {
        AesCipherParams params;
        params.encrypt = isEncrypt ? 1 : 0;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password"};
        }

        return params;
    }
};

CryptoGuardCtx::CryptoGuardCtx() { pImpl_ = std::make_unique<Impl>(); }

CryptoGuardCtx::~CryptoGuardCtx() = default;

/**
 * @brief Шифрование данных
 *
 * @param inStream  Поток входных данных, которые нужно зашифровать
 * @param outStream Поток выходных данных, куда будут записаны данные в зашифрованном виде
 * @param password  Пароль для шифрования
 */
void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}

/**
 * @brief Расшифровка данных
 *
 * @param inStream  Поток входных зашифрованных данных
 * @param outStream Поток выходных данных, куда будут записаны данные в расшифрованном виде
 * @param password  Пароль для расшифровки
 */
void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}

/**
 * @brief Получение контрольной суммы для данных
 *
 * @param inStream Поток данных, контрольную сумму которых нужно посчитать
 * @return std::string Контрольную сумму в виде хэша
 */
std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); }
}  // namespace CryptoGuard
