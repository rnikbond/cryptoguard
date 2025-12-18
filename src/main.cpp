#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>

int main(int argc, char *argv[]) {
    try {
        //
        // OpenSSL пример использования:
        //
        // std::string input = "01234567890123456789";
        // std::string output;

        // OpenSSL_add_all_algorithms();

        // auto params = CreateChiperParamsFromPassword("12341234");
        // params.encrypt = 1;
        // auto *ctx = EVP_CIPHER_CTX_new();

        // // Инициализируем cipher
        // EVP_CipherInit_ex(ctx, params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);

        // std::vector<unsigned char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);
        // std::vector<unsigned char> inBuf(16);
        // int outLen;

        // // Обрабатываем первые N символов
        // std::copy(input.begin(), std::next(input.begin(), 16), inBuf.begin());
        // EVP_CipherUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(16));
        // for (int i = 0; i < outLen; ++i) {
        //     output.push_back(outBuf[i]);
        // }

        // // Обрабатываем оставшиеся символы
        // std::copy(std::next(input.begin(), 16), input.end(), inBuf.begin());
        // EVP_CipherUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(input.size() - 16));
        // for (int i = 0; i < outLen; ++i) {
        //     output.push_back(outBuf[i]);
        // }

        // // Заканчиваем работу с cipher
        // EVP_CipherFinal_ex(ctx, outBuf.data(), &outLen);
        // for (int i = 0; i < outLen; ++i) {
        //     output.push_back(outBuf[i]);
        // }
        // EVP_CIPHER_CTX_free(ctx);
        // std::print("String encoded successfully. Result: '{}'\n\n", output);
        // EVP_cleanup();
        //
        // Конец примера
        //

        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

        std::fstream input(options.GetInputFile(), std::ios::in | std::ios::binary);

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        switch (options.GetCommand()) {
        case CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT: {
            std::fstream output(options.GetOutputFile(), std::ios::out | std::ios::binary);
            cryptoCtx.EncryptFile(input, output, options.GetPassword());
            break;
        }
        case CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT: {
            std::fstream output(options.GetOutputFile(), std::ios::out | std::ios::binary);
            cryptoCtx.DecryptFile(input, output, options.GetPassword());
            break;
        }
        case CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM: {
            std::print(std::cout, "{}\n", cryptoCtx.CalculateChecksum(input));
            break;
        }
        default:
            throw std::runtime_error{"unknown command"};
        }

        // std::ios::binary - флаг открытия файла для шифрования

        // CryptoGuard::CryptoGuardCtx cryptoCtx;

        // using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}