#include <vector>
#include <memory>
#include <string>
#include <map>
#include <iterator>

#include "ber.h"

namespace Ldap {
    enum class MessageTag : uint8_t {
        BindRequest = 0,
        BindResponse = 1,
        UnbindRequest = 2,
        SearchRequest = 3,
        SearchResEntry = 4,
        SearchResDone = 5,
        SearchResRef = 19,
        ModifyRequest = 6,
        ModifyResponse = 7,
        AddRequest = 8,
        AddResponse = 9,
        DelRequest = 10,
        DelResponse = 11,
        ModDNRequest = 12,
        ModDNResponse = 13,
        CompareRequest = 14,
        CompareResponse = 15,
        AbandonRequest = 16,
        ExtendedRequest = 23,
        ExtendedResponse = 24,
        IntermediateResponse = 25
    };

    struct Entry {
        std::string dn;
        std::map<std::string, std::vector<std::string>> attributes;

        Entry(std::string _dn):
            dn(_dn),
            attributes()
        { }

        Entry():
            dn {},
            attributes {}
        { }

        void appendValue(std::string name, std::string value);
    };

    Ber::Packet buildLdapResult(
        int code,
        std::string matchedDn,
        std::string errMsg,
        MessageTag tag);

namespace Search {

    struct SubFilter {
        enum class Type { Initial, Any, Final } type;
        std::string value;
    };

    struct Filter {
        enum class Type { And, Or, Not, Eq, Sub, Gte, Lte, Present, Approx, Extensible } type;
        std::vector<Filter> children;
        std::vector<SubFilter> subChildren;
        std::string value;
        std::string attributeName;
    };

    struct Request {
        std::string base;
        enum class Scope { Base, One, Sub } scope;
        enum class DerefAliases { Never, Searching, Finding, Always } derefAliases;
        int sizeLimit;
        int timeLimit;
        bool typesOnly;
        Filter filter;
        std::vector<std::string> attributes;

        Request(const Ber::Packet p);
    };

    Ber::Packet generateResult(const Ldap::Entry& e);

} // namespace Search

namespace Bind {

    struct Request {
        int version;
        std::string dn;
        std::string simple;
        std::string saslMech;
        std::vector<uint8_t> saslCredentials;

        enum class Type { Simple = 0, Sasl = 3 } type;

        Request(const Ber::Packet p);
    };

    struct Response {
        Ber::Packet response;
        Response(Ber::Packet result);
        void appendSaslResponse(std::vector<uint8_t> resp);
    };

} // namespace bind

namespace Add {
    Ldap::Entry parseRequest(Ber::Packet p);
} // namespace Add

namespace Delete {
    std::string parseRequest(Ber::Packet p);
} // namespace Delete
} // namespace Ldap
