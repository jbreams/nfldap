#include <vector>
#include <memory>
#include <string>
#include <map>
#include <iterator>

#include <boost/utility/string_ref.hpp>
#include <boost/optional.hpp>

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

        boost::optional<std::vector<std::string>&> find(std::string key){
            boost::optional<std::vector<std::string>&> ret;
            auto it = attributes.find(key);
            if (it == attributes.end())
                return ret;
            ret = it->second;
            return ret;
        }

        std::map<std::string, std::vector<std::string>>::iterator begin() {
            return attributes.begin();
        }

        std::map<std::string, std::vector<std::string>>::iterator end() {
            return attributes.end();
        }

        std::map<std::string, std::vector<std::string>>::const_iterator cbegin() {
            return attributes.cbegin();
        }

        std::map<std::string, std::vector<std::string>>::const_iterator cend() {
            return attributes.cend();
        }
    };

    Ber::Packet buildLdapResult(
        Ldap::ErrorCode code,
        std::string matchedDn,
        std::string errMsg,
        MessageTag tag);

    struct SubFilter {
        enum class Type { Initial, Any, Final } type;
        std::string value;

        SubFilter(Type t, std::string v) :
            type {t},
            value { std::move(v) }
        {}
    };
    bool operator<(const SubFilter lhs, const SubFilter rhs);
    bool operator==(const SubFilter lhs, const SubFilter rhs);

    struct Filter {
        enum class Type {
            None, And, Or, Not, Eq, Sub, Gte, Lte, Present, Approx, Extensible
        } type = Type::None;

        Filter(Type t, std::string a) :
            type { t },
            attributeName { std::move(a) }
        {}

        Filter(Type t, std::string a, std::string v) :
            type { t },
            value { std::move(v) },
            attributeName { std::move(a) }
        {}

        Filter(Type t, std::vector<Filter> c) :
            type { t },
            children { std::move(c) }
        {}

        Filter(std::string a, std::vector<SubFilter> c) :
            type { Type::Sub },
            subChildren { std::move(c) },
            attributeName { std::move(a) }
        {}

        Filter() = default;

        std::vector<Filter> children{};
        std::vector<SubFilter> subChildren{};
        std::string value = "";
        std::string attributeName = "";

        bool match(const Entry& e);

    };

    Filter parseFilter(const Ber::Packet& p);
    Filter parseFilter(const std::string& p);
    Filter parseFilter(boost::string_ref p);
    bool operator<(const Filter lhs, const Filter rhs);
    bool operator==(const Filter lhs, const Filter rhs);


namespace Search {


    struct Request {
        std::string base;
        enum class Scope { Base, One, Sub } scope;
        enum class DerefAliases { Never, Searching, Finding, Always } derefAliases;
        int sizeLimit;
        int timeLimit;
        bool typesOnly;
        Ldap::Filter filter;
        std::vector<std::string> attributes;

        Request(const Ber::Packet p);
    };

    Ber::Packet generateResult(const Ldap::Entry& e);

} // namespace Search

namespace Modify {

    struct Modification {
        Modification(const Ber::Packet p);
        enum class Type { Add, Delete, Replace } type;
        std::vector<std::string> values;
        std::string name;
    };

    struct Request {
        std::string dn;
        std::vector<Modification> mods;

        Request(const Ber::Packet p);
    };

} //namespace Modify

namespace Bind {

    struct Request {
        int version;
        std::string dn;
        std::string simple;
        std::string saslMech;
        std::vector<uint8_t> saslCredentials;

        enum class Type { Simple = 0, Sasl = 3 } type;

        Request(const Ber::Packet& p);
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
