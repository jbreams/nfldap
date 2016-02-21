#include <iterator>
#include <fstream>
#include <sstream>
#include <vector>

#include <sodium.h>

#include "passwords.h"

namespace Password {

const std::string PasswordSchemeName = "{NF-SODIUM-V1}";

std::string generatePassword(const std::string password) {
    char checksum[crypto_pwhash_scryptsalsa208sha256_STRBYTES];

    unsigned long long opslimit = crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE;
    unsigned long long memlimit = crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE;

    if (crypto_pwhash_scryptsalsa208sha256_str(
        checksum,
        password.c_str(),
        static_cast<unsigned long long>(password.size()),
        opslimit,
        memlimit) == -1) {
        throw std::runtime_error("error hashing password");
    }

    std::stringstream strBuf;
    strBuf << PasswordSchemeName << checksum;
    return strBuf.str();
}

bool checkPassword(std::string password, std::string rawHashedPassword) {
    if (rawHashedPassword.find(PasswordSchemeName) != 0)
        throw std::invalid_argument("hashed password has invalid scheme");

    std::vector<char> hashedPassword;
    std::copy(rawHashedPassword.begin() + PasswordSchemeName.size(), rawHashedPassword.end(),
            std::back_inserter(hashedPassword));

    auto rc = crypto_pwhash_scryptsalsa208sha256_str_verify(
        hashedPassword.data(),
        password.c_str(),
        password.size()
    );
    return rc == 0;
}

void init() {
    if (sodium_init() == -1) {
        throw std::runtime_error("error inititalizing libsodium");
    }
}

} // namespace Password
