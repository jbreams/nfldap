#include "exceptions.h"
#include <map>

namespace Ldap {
namespace {
const std::map<ErrorCode, std::string> errorStrings{
    { ErrorCode::success, "success" },
    { ErrorCode::operationsError, "operationsError" },
    { ErrorCode::protocolError, "protocolError" },
    { ErrorCode::timeLimitExceeded, "timeLimitExceeded" },
    { ErrorCode::sizeLimitExceeded, "sizeLimitExceeded" },
    { ErrorCode::compareFalse, "compareFalse" },
    { ErrorCode::compareTrue, "compareTrue" },
    { ErrorCode::authMethodNotSupported, "authMethodNotSupported" },
    { ErrorCode::strongerAuthRequired, "strongerAuthRequired" },
    { ErrorCode::referral, "referral" },
    { ErrorCode::adminLimitExceeded, "adminLimitExceeded" },
    { ErrorCode::unavailableCriticalExtension, "unavailableCriticalExtension" },
    { ErrorCode::confidentialityRequired, "confidentialityRequired" },
    { ErrorCode::saslBindInProgress, "saslBindInProgress" },
    { ErrorCode::noSuchAttribute, "noSuchAttribute" },
    { ErrorCode::undefinedAttributeType, "undefinedAttributeType" },
    { ErrorCode::inappropriateMatching, "inappropriateMatching" },
    { ErrorCode::constraintViolation, "constraintViolation" },
    { ErrorCode::attributeOrValueExists, "attributeOrValueExists" },
    { ErrorCode::invalidAttributeSyntax, "invalidAttributeSyntax" },
    { ErrorCode::noSuchObject, "noSuchObject" },
    { ErrorCode::aliasProblem, "aliasProblem" },
    { ErrorCode::invalidDNSyntax, "invalidDNSyntax" },
    { ErrorCode::aliasDereferencingProblem, "aliasDereferencingProblem" },
    { ErrorCode::inappropriateAuthentication, "inappropriateAuthentication" },
    { ErrorCode::invalidCredentials, "invalidCredentials" },
    { ErrorCode::insufficientAccessRights, "insufficientAccessRights" },
    { ErrorCode::busy, "busy" },
    { ErrorCode::unavailable, "unavailable" },
    { ErrorCode::unwillingToPerform, "unwillingToPerform" },
    { ErrorCode::loopDetect, "loopDetect" },
    { ErrorCode::namingViolation, "namingViolation" },
    { ErrorCode::objectClassViolation, "objectClassViolation" },
    { ErrorCode::notAllowedOnNonLeaf, "notAllowedOnNonLeaf" },
    { ErrorCode::notAllowedOnRDN, "notAllowedOnRDN" },
    { ErrorCode::entryAlreadyExists, "entryAlreadyExists" },
    { ErrorCode::objectClassModsProhibited, "objectClassModsProhibited" },
    { ErrorCode::affectsMultipleDSAs, "affectsMultipleDSAs" },
    { ErrorCode::other, "other" },
};
} // namespace

Exception::Exception(ErrorCode code) :
    _code { code },
    _what { errorStrings.at(code) }
{}

Exception::Exception(ErrorCode code, const char* what) :
    _code { code },
    _what { what }
{}

void checkProtocolError(bool exprResult) {
    if (!exprResult) {
        throw Exception(ErrorCode::protocolError);
    }
}
} // namespace Ldap
