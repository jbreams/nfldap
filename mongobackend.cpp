#include <string>
#include <iostream>
#include <sstream>

#include <boost/algorithm/string.hpp>
#include <boost/tokenizer.hpp>
#include <boost/range/adaptor/reversed.hpp>

#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/uri.hpp>

#include <bsoncxx/builder/basic/array.hpp>
#include <bsoncxx/builder/basic/document.hpp>
#include <bsoncxx/builder/basic/kvp.hpp>
#include <bsoncxx/types.hpp>
#include <bsoncxx/json.hpp>

#include "ldapproto.h"
#include "storage.h"

namespace Storage {
namespace Mongo {

using bsoncxx::builder::basic::document;
using bsoncxx::builder::basic::array;
using bsoncxx::builder::basic::kvp;
using bsoncxx::builder::basic::sub_document;
using bsoncxx::builder::basic::sub_array;

std::list<std::string> dnToList(std::string dn) {
    std::list<std::string> dnParts;

    using tokenizer = boost::tokenizer<boost::escaped_list_separator<char>>;
    tokenizer tok(dn);

    for (tokenizer::iterator dnIt = tok.begin(); dnIt != tok.end(); ++dnIt)
    {
        auto part = std::string{*dnIt};
        auto eqPos = part.find("=");
        assert(eqPos != std::string::npos);
        assert(part.size() > eqPos + 1);
        auto varName = part.substr(0, eqPos);
        auto varValue = part.substr(eqPos + 1);
        boost::to_lower(varName);
        boost::trim(varName);
        boost::trim(varValue);

        std::stringstream valBuf;
        valBuf << varName << "=" << varValue;
        dnParts.push_back(valBuf.str());
    }

    return dnParts;
}

std::string dnPartsToId(const std::list<std::string>& parts) {
    std::list<std::string> reversedList(parts.rbegin(), parts.rend());
    return boost::algorithm::join(reversedList, ",");
}

MongoCursor::iterator& MongoCursor::iterator::operator++() {
    ++_cursorIt;
    return *this;
}

void MongoCursor::iterator::refreshDocument() {
    auto resultDoc = *_cursorIt;
    std::string dn{ resultDoc["_id"].get_utf8().value };
    dn = dnPartsToId(dnToList(dn));
    curEntry = Ldap::Entry { dn };

    for (bsoncxx::document::element el: resultDoc) {
        // We've already parsed the _id above
        std::string key{ el.key() };
        if (key == "_id") {
            continue;
        }

        switch(el.type()) {
            case bsoncxx::type::k_utf8:
                curEntry.appendValue(key, std::string{ el.get_utf8().value });
                break;
            case bsoncxx::type::k_array: {
                bsoncxx::array::view values{el.get_array().value};
                for (bsoncxx::array::element subEl: values) {
                    curEntry.appendValue(key, std::string { subEl.get_utf8().value });
                }
                                         }
                break;
            default:
                break;
        }
    }
}

MongoCursor::iterator MongoCursor::begin() {
    return iterator{_cursor.begin()};
}

MongoCursor::iterator MongoCursor::end() {
    return iterator{_cursor.end()};
}

MongoBackend::MongoBackend(
    std::string connectURI,
    std::string db,
    std::string collection,
    std::string rootDN
) :
    _client { mongocxx::uri { connectURI } },
    _collection { _client[db][collection] },
    _rootdn { rootDN }
{}

void MongoBackend::saveEntry(Ldap::Entry e) {
    std::string dnId = dnPartsToId(dnToList(e.dn));
    auto opts = mongocxx::options::update();

    auto filterDoc = document{};
    auto updateDoc = document{};

    filterDoc.append(kvp("_id", dnId));
    updateDoc.append(kvp("_id", dnId));

    for (auto && attr: e.attributes) {
        auto values = attr.second;
        if (values.size() > 1) {
            updateDoc.append(kvp(attr.first, [values](sub_array subArray) {
                for(auto && v: values) {
                    subArray.append(v);
                }
            }));
        } else {
            updateDoc.append(kvp(attr.first, values[0]));
        }
    }

    opts.upsert(true);
    _collection.replace_one(filterDoc.view(), updateDoc.view(), opts);
}

std::unique_ptr<Ldap::Entry> MongoBackend::findEntry(std::string dn) {
    auto e = std::unique_ptr<Ldap::Entry>{new Ldap::Entry{dn}};
    auto searchDoc = document{};
    searchDoc.append(kvp("_id", dnPartsToId(dnToList(dn))));
    auto resultDoc = _collection.find_one(searchDoc.view());
    if (!resultDoc)
        return nullptr;

    for (bsoncxx::document::element el: resultDoc->view()) {
        // We've already parsed the _id above
        std::string key{ el.key() };
        if (key == "_id") {
            continue;
        }

        switch(el.type()) {
            case bsoncxx::type::k_utf8:
                e->appendValue(key, std::string{ el.get_utf8().value });
                break;
            case bsoncxx::type::k_array: {
                bsoncxx::array::view values{el.get_array().value};
                for (bsoncxx::array::element subEl: values) {
                    e->appendValue(key, std::string { subEl.get_utf8().value });
                }
                                         }
                break;
            default:
                break;
        }
    }

    return e;
}

void processFilter(Ldap::Search::Filter filter, sub_document & searchDoc) {
    using Type = Ldap::Search::Filter::Type;
    switch (filter.type) {
        case Type::And:
            searchDoc.append(kvp("$and", [filter](sub_array arr) {
                for (auto && c: filter.children) {
                    arr.append([c](sub_document subDoc) {
                        processFilter(c, subDoc);
                    });
                }
            }));
            break;
        case Type::Or:
            searchDoc.append(kvp("$or", [filter](sub_array arr) {
                for (auto && c: filter.children) {
                    arr.append([c](sub_document subDoc) {
                        processFilter(c, subDoc);
                    });
                }
            }));
            break;
        case Type::Not:
            searchDoc.append(kvp("$not", [filter](sub_document subDoc) {
                processFilter(filter.children[0], subDoc);
                }));
            break;
        case Type::Eq:
            searchDoc.append(kvp(filter.attributeName, filter.value));
            break;
        case Type::Sub: {
            using SubType = Ldap::Search::SubFilter::Type;
            std::stringstream subBuffer;
            for (auto && c: filter.subChildren) {
                switch(c.type) {
                case SubType::Initial:
                    subBuffer << "^" << c.value;
                    break;
                case SubType::Any:
                    subBuffer << ".+" << c.value;
                    break;
                case SubType::Final:
                    subBuffer << ".+" << c.value << "$";
                    break;
                }
            }
            searchDoc.append(kvp(filter.attributeName,
                    bsoncxx::types::b_regex{ subBuffer.str(), "" }));
                        }
            break;
        case Type::Gte:
            searchDoc.append(kvp(filter.attributeName, [filter](sub_document gteDoc) {
                gteDoc.append(kvp("$gte", filter.value));
            }));
            break;
        case Type::Lte:
            searchDoc.append(kvp(filter.attributeName, [filter](sub_document lteDoc) {
                lteDoc.append(kvp("$lte", filter.value));
            }));
            break;
        case Type::Present:
            searchDoc.append(kvp(filter.attributeName, [](sub_document lteDoc) {
                lteDoc.append(kvp("$exists", true));
            }));
            break;
        case Type::Approx:
        case Type::Extensible:
            // TODO implement these!
            assert(false);
            break;
    }
}

std::unique_ptr<MongoCursor> MongoBackend::findEntries(Ldap::Search::Request req) {
    auto searchDocument = document{};
    auto baseDnId = dnPartsToId(dnToList(req.base));
    using Scope = Ldap::Search::Request::Scope;

    std::stringstream regexBuf;
    regexBuf << "^" << baseDnId;
    switch(req.scope) {
    case Scope::One:
        regexBuf << ",?[^,]+";
        break;
    case Scope::Sub:
        regexBuf << ",?.+";
        break;
    case Scope::Base:
        regexBuf << "$";
        break;
    }
    searchDocument.append(kvp("_id", bsoncxx::types::b_regex{ regexBuf.str(), "" }));
    processFilter(req.filter, searchDocument);

    mongocxx::options::find opts;
    if (req.sizeLimit > 0) {
        opts.limit(req.sizeLimit);
    }

    if (req.timeLimit > 0) {
        opts.max_time(std::chrono::milliseconds{req.timeLimit * 1000});
    }

    if (req.attributes.size() > 0) {
        auto projection = document{};
        if (req.attributes[0] == "1.1") {
            projection.append(kvp("_id", 1));
        }
        else if(req.attributes[0] != "*") {
            for (auto && attr: req.attributes) {
                projection.append(kvp(attr, 1));
            }
        }
        opts.projection(projection.extract());
    }

    auto view = searchDocument.view();
    std::cout << bsoncxx::to_json(view);
    auto cursor = _collection.find(view, opts);
    return std::unique_ptr<MongoCursor>(new MongoCursor{ std::move(cursor) });
}

void MongoBackend::deleteEntry(std::string dn) {
    auto searchDoc = document{};
    searchDoc.append(kvp("_id", dnPartsToId(dnToList(dn))));
    _collection.delete_one(searchDoc.view());
}

} // namespace Mongo
} // namespace Storage
