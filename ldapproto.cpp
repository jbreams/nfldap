#include "ldapproto.h"

#include "exceptions.h"

namespace Ldap {
Ber::Packet buildLdapResult(int code, std::string matchedDn, std::string errMsg, MessageTag tag) {
    Ber::Packet response(Ber::Type::Constructed, Ber::Class::Application,
        static_cast<uint8_t>(tag));
    response.appendChild(Ber::Packet(Ber::Tag::Enumerated, static_cast<uint64_t>(code)));
    response.appendChild(Ber::Packet(Ber::Tag::OctetString, matchedDn));
    response.appendChild(Ber::Packet(Ber::Tag::OctetString, errMsg));
    return response;
};

template<typename T>
void checkProtocolErrorTagMatches(T tagEnum, uint8_t tag) {
    uint8_t tagEnumByte = static_cast<uint8_t>(tagEnum);
    checkProtocolError(tag == tagEnumByte);
}

template<typename T>
void checkProtocolErrorTagRange(T tagMin, T tagMax, uint8_t val) {
    checkProtocolError(val >= static_cast<uint8_t>(tagMin) &&
            val <= static_cast<uint8_t>(tagMax));
}

void Entry::appendValue(std::string name, std::string value) {
    attributes[name].push_back(value);
}

namespace Bind {

Request::Request(const Ber::Packet p) {
    checkProtocolErrorTagMatches<Ber::Tag>(Ber::Tag::Integer, p.children[0].tag);
    version = p.children[0];

    checkProtocolErrorTagMatches<Ber::Tag>(Ber::Tag::OctetString, p.children[1].tag);
    dn = std::string(p.children[1]);

    type = static_cast<Type>(static_cast<int>(p.children[2]));
    checkProtocolError(type == Type::Simple || type == Type::Sasl);
    if (type == Type::Simple) {
        if (p.children.size() == 4)
            simple = std::string(p.children[3]);
    } else if (type == Type::Sasl) {
        if (p.children.size() == 6) {
            saslMech = std::string(p.children[3]);
            saslCredentials = p.children[4].data;
        }
    }
}

Response::Response(Ber::Packet result):
    response(result)
{ }

void Response::appendSaslResponse(std::vector<uint8_t> resp) {
    Ber::Packet saslData(Ber::Tag::OctetString, resp.begin(), resp.end());
    response.appendChild(saslData);
}

} // namespace bind

namespace Search {
Filter parseFilter(const Ber::Packet& p) {
    Filter ret;
    checkProtocolErrorTagRange<Filter::Type>(Filter::Type::And, Filter::Type::Extensible, p.tag);
    Filter::Type type = static_cast<Filter::Type>(p.tag);
    ret.type = type;
    switch(type) {
    case Filter::Type::And:
    case Filter::Type::Or:
        checkProtocolError(p.children.size() >= 2);
        for (auto && c: p.children) {
            ret.children.push_back(parseFilter(c));
        }
        break;
    case Filter::Type::Not:
        checkProtocolError(p.children.size() == 1);
        ret.children.push_back(parseFilter(p.children[0]));
        break;
    case Filter::Type::Sub:
        checkProtocolError(p.children.size() == 2);
        ret.attributeName = std::string(p.children[0]);
        for (auto && c: p.children[1].children) {
            SubFilter sf {
                static_cast<SubFilter::Type>(c.tag),
                std::string(c)
            };
            ret.subChildren.push_back(sf);
        }
        break;
    case Filter::Type::Extensible:
        break;
    case Filter::Type::Present:
        ret.attributeName = std::string(p);
        break;
    case Filter::Type::Eq:
    case Filter::Type::Gte:
    case Filter::Type::Lte:
    case Filter::Type::Approx:
        checkProtocolError(p.children.size() == 2);
        ret.attributeName = std::string(p.children[0]);
        ret.value = std::string{ p.children[1].data.begin(), p.children[1].data.end() };
        break;
    }

    return ret;
}

Request::Request(const Ber::Packet p) {
    // Basic sanity checks
    checkProtocolErrorTagMatches<Ldap::MessageTag>(Ldap::MessageTag::SearchRequest, p.tag);
    checkProtocolError(p.children.size() == 8);

    checkProtocolErrorTagMatches<Ber::Tag>(Ber::Tag::OctetString, p.children[0].tag);
    base = std::string(p.children[0]);

    checkProtocolErrorTagMatches<Ber::Tag>(Ber::Tag::Enumerated, p.children[1].tag);
    checkProtocolErrorTagRange<Scope>(Scope::Base, Scope::Sub, static_cast<uint64_t>(p.children[1]));
    scope = static_cast<Scope>(static_cast<uint64_t>(p.children[1]));

    checkProtocolErrorTagMatches<Ber::Tag>(Ber::Tag::Enumerated, p.children[2].tag);
    checkProtocolErrorTagRange<DerefAliases>(DerefAliases::Never, DerefAliases::Always,
            static_cast<uint64_t>(p.children[2]));
    derefAliases = static_cast<DerefAliases>(static_cast<uint64_t>(p.children[2]));

    checkProtocolErrorTagMatches<Ber::Tag>(Ber::Tag::Integer, p.children[3].tag);
    sizeLimit = p.children[3];

    checkProtocolErrorTagMatches<Ber::Tag>(Ber::Tag::Integer, p.children[4].tag);
    timeLimit = p.children[4];

    checkProtocolErrorTagMatches<Ber::Tag>(Ber::Tag::Boolean, p.children[5].tag);
    typesOnly = p.children[5];

    filter = parseFilter(p.children[6]);

    checkProtocolErrorTagMatches<Ber::Tag>(Ber::Tag::Sequence, p.children[7].tag);
    for (auto & a: p.children[7].children) {
        checkProtocolErrorTagMatches<Ber::Tag>(Ber::Tag::OctetString, a.tag);
        std::string attr(a);
        attributes.push_back(attr);
    }
}


Ber::Packet generateResult(const Ldap::Entry& entry) {
    Ber::Packet response(Ber::Type::Constructed, Ber::Class::Application, 4);
    response.appendChild(Ber::Packet(Ber::Tag::OctetString, entry.dn));

    Ber::Packet attrRoot(Ber::Type::Constructed, Ber::Class::Universal, Ber::Tag::Sequence);
    for (auto const & attr: entry.attributes) {
        Ber::Packet attrPacket(Ber::Type::Constructed, Ber::Class::Universal, Ber::Tag::Sequence);
        attrPacket.appendChild(Ber::Packet(Ber::Tag::OctetString, attr.first));
        Ber::Packet attrValues(Ber::Type::Constructed, Ber::Class::Universal, Ber::Tag::Set);
        for (auto && val: attr.second) {
            Ber::Packet valPacket(Ber::Tag::OctetString, val);
            attrValues.appendChild(valPacket);
        }
        attrPacket.appendChild(attrValues);
        attrRoot.appendChild(attrPacket);
    }
    response.appendChild(attrRoot);
    return response;
}

} // namespace search

namespace Add {
Entry parseRequest(Ber::Packet p) {
    checkProtocolErrorTagMatches<Ldap::MessageTag>(Ldap::MessageTag::AddRequest, p.tag);
    checkProtocolErrorTagMatches<Ber::Tag>(Ber::Tag::OctetString, p.children[0].tag);
    Entry ret(p.children[0]);

    Ber::Packet attrs = p.children[1];
    checkProtocolErrorTagMatches<Ber::Tag>(Ber::Tag::Sequence, attrs.tag);
    for (auto attrSeq: attrs.children) {
        checkProtocolErrorTagMatches<Ber::Tag>(Ber::Tag::Sequence, attrSeq.tag);
        checkProtocolErrorTagMatches<Ber::Tag>(Ber::Tag::OctetString, attrSeq.children[0].tag);
        checkProtocolErrorTagMatches<Ber::Tag>(Ber::Tag::Set, attrSeq.children[1].tag);
        for (auto attrVal: attrSeq.children[1].children) {
            checkProtocolErrorTagMatches<Ber::Tag>(Ber::Tag::OctetString, attrVal.tag);
            ret.appendValue(attrSeq.children[0], attrVal);
        }
    }
    return ret;
}

} // namespace add

namespace Delete {
std::string parseRequest(Ber::Packet p) {
    checkProtocolErrorTagMatches<Ldap::MessageTag>(Ldap::MessageTag::DelRequest, p.tag);
    return static_cast<std::string>(p);
}
}
} // namespace ldap
