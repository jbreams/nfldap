#include <iterator>
#include <fstream>
#include <sstream>
#include <vector>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "passwords.h"

namespace Password {

const std::string PasswordSchemeName = "{NF-PBKDF2-V1}";
const auto saltLength = 32;
const auto keyLength = 128;
const auto pbkdfRounds = 10000;

// This is a password hashing scheme for no frills LDAP. It uses PBKDF2 to hash your password
// 10000 times with a salt with SHA215 as the HMAC algorithm.
//
// The name of the scheme encoded in the hash string is NF-PBKDF2-V1, signifying the algorithm
// used to derive the key, that this is super specific to no frills LDAP, and that I may come
// up with a better scheme later.
//
// Ideally, this will support different schemes later, but I wanted to support real binds early
// on.
std::string computeHash(const std::string password, const std::vector<uint8_t> salt) {
    std::vector<uint8_t> rawChecksum(keyLength);
    PKCS5_PBKDF2_HMAC(
        password.c_str(),
        password.size(),
        salt.data(),
        salt.size(),
        pbkdfRounds,
        EVP_sha512(),
        rawChecksum.size(),
        rawChecksum.data()
    );

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, salt.data(), salt.size());
    BIO_write(bio, rawChecksum.data(), rawChecksum.size());
    BIO_flush(bio);

    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::stringstream strBuf;
    strBuf << PasswordSchemeName << bufferPtr->data;
    BIO_free_all(bio);

    return strBuf.str();
}

size_t base64Length(const std::vector<uint8_t> s) {
    auto padding = 0;

    if (s[s.size() - 1] == '=' && s[s.size() - 2] == '=')
        padding = 2;
    else if (s[s.size() - 1] == '=')
        padding = 1;

    return (s.size() * 3) / 4 - padding;
}

std::string generatePassword(std::string password) {
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    urandom.unsetf(std::ios::skipws);

    std::vector<uint8_t> saltVector(saltLength);
    urandom.read(reinterpret_cast<char*>(saltVector.data()), saltVector.size());

    return computeHash(password, saltVector);
}

bool checkPassword(std::string password, std::string rawHashedPassword) {
    if (rawHashedPassword.find(PasswordSchemeName) != 0)
        throw std::invalid_argument("hashed password has invalid scheme");

    std::vector<uint8_t> hashedPassword;
    std::copy(rawHashedPassword.begin() + PasswordSchemeName.size(), rawHashedPassword.end(),
            std::back_inserter(hashedPassword));
    auto decodeLen = base64Length(hashedPassword);
    if (decodeLen != (saltLength + keyLength))
        throw std::invalid_argument("hashed password has invalid length");

    auto bio = BIO_new_mem_buf(
        hashedPassword.data(),
        hashedPassword.size()
    );
    auto b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    std::vector<uint8_t> saltVector(saltLength);
    BIO_read(bio, saltVector.data(), saltVector.size());
    BIO_free_all(bio);

    auto checkHash = computeHash(password, saltVector);

    if (rawHashedPassword.size() != checkHash.size())
        return false;

    uint8_t xorByte = 0;
    for (size_t i = 0; i < checkHash.size(); i++) {
        xorByte |= checkHash[i] ^ rawHashedPassword[i];
    }
    return xorByte == 0;
}

} // namespace Password
