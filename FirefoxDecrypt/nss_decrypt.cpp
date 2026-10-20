#include "nss_decrypt.h"

std::string GetNssConfigPath(const std::filesystem::path& profile) {
    if (std::filesystem::exists(profile / "key4.db") &&
        std::filesystem::exists(profile / "cert9.db")) {
        return "sql:" + WideToUtf8(profile.wstring());
    }
    if (std::filesystem::exists(profile / "key3.db") &&
        std::filesystem::exists(profile / "cert8.db")) {
        return WideToUtf8(profile.wstring());
    }
    throw std::runtime_error(
        "Profile does not contain key4.db/cert9.db or key3.db/cert8.db.");
}

std::string Decrypt(PK11SDRDecryptFn decrypt, SECItemZfreeItemFn freeItem,
    const std::string& encoded) 
{
    std::vector<unsigned char> ciphertext = DecodeBase64(encoded);
    if (ciphertext.empty())
        throw std::runtime_error("Encrypted login field is empty.");

    SECItem input{ 0, ciphertext.data(),
                  static_cast<unsigned int>(ciphertext.size()) };
    SECItem output{};
    if (decrypt(&input, &output, nullptr) != 0) {
        if (output.data)
            freeItem(&output, 0);
        throw std::runtime_error(
            "NSS decryption failed; check the Primary Password and profile.");
    }

    std::string plaintext;
    if (output.len > 0) {
        if (!output.data) {
            freeItem(&output, 0);
            throw std::runtime_error("NSS returned an invalid decrypted value.");
        }
        plaintext.assign(reinterpret_cast<const char*>(output.data), output.len);
    }
    if (output.data)
        freeItem(&output, 0);
    return plaintext;
}