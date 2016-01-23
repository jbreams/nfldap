#include <exception>
#include <string>

namespace Ldap {

enum class ErrorCode: int {
    success = 0,
    operationsError = 1,
    protocolError = 2,
    timeLimitExceeded = 3,
    sizeLimitExceeded = 4,
    compareFalse = 5,
    compareTrue = 6,
    authMethodNotSupported = 7,
    strongerAuthRequired = 8,
    referral = 10,
    adminLimitExceeded = 11,
    unavailableCriticalExtension = 12,
    confidentialityRequired = 13,
    saslBindInProgress = 14,
    noSuchAttribute = 16,
    undefinedAttributeType = 17,
    inappropriateMatching = 18,
    constraintViolation = 19,
    attributeOrValueExists = 20,
    invalidAttributeSyntax = 21,
    noSuchObject = 32,
    aliasProblem = 33,
    invalidDNSyntax = 34,
    aliasDereferencingProblem = 36,
    inappropriateAuthentication = 48,
    invalidCredentials = 49,
    insufficientAccessRights = 50,
    busy = 51,
    unavailable = 52,
    unwillingToPerform = 53,
    loopDetect = 54,
    namingViolation = 64,
    objectClassViolation = 65,
    notAllowedOnNonLeaf = 66,
    notAllowedOnRDN = 67,
    entryAlreadyExists = 68,
    objectClassModsProhibited = 69,
    affectsMultipleDSAs = 71,
    other = 80
};

class Exception: public std::exception
{
public:
    Exception(ErrorCode code);
    Exception(ErrorCode code, const char* what);

    virtual const char* what() const throw() {
        return _what.c_str();
    };

    operator int() const {
        return static_cast<int>(_code);
    };

private:
    ErrorCode _code;
    const std::string _what;
};

// Use this instead of asserting when decoding and parsing protocol data
void checkProtocolError(bool exprResult);

} // namespace Ldap
