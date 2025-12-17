#include "crypto_guard_ctx.h"
#include <memory>

namespace CryptoGuard {

class CryptoGuardCtx::Impl {
public:
    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {}
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {}
    std::string CalculateChecksum(std::iostream &inStream) { return "NOT_IMPLEMENTED"; }
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
    pImpl_->EncryptFile(inStream, outStream, password);
}

/**
 * @brief Получение контрольной суммы для данных
 *
 * @param inStream Поток данных, контрольную сумму которых нужно посчитать
 * @return std::string Контрольную сумму в виде хэша
 */
std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); }
}  // namespace CryptoGuard
