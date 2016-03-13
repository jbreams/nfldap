#include <mutex>
#include <thread>
#include <set>

#include <unistd.h>

#include <boost/algorithm/string.hpp>
#include <boost/utility/string_ref.hpp>
#include <boost/optional.hpp>

#include "exceptions.h"
#include "ldapproto.h"
#include "access.h"
#include "storage.h"

#include "loguru.hpp"

namespace Ldap {
namespace Access {

Entry::Entry(const std::string& str) {
    tokenizer tok(str);
    auto it = tok.begin();

    // This is kind of a silly check, but making sure it starts with a "to" makes sure
    // it conforms to some kind of spec??
    {
        boost::string_ref toStr{*it++};
        if (toStr != "to") {
            LOG_S(ERROR) << "access directive doesn't start with \"to\": " << toStr;
            throw Ldap::Exception(Ldap::ErrorCode::protocolError);
        }
    }

    boost::string_ref whatStr{*it++};
    if (whatStr == "*") {
        scope = Scope::All;
    }
    else {
        do {
            auto eqPos = whatStr.find('=');
            if (eqPos == std::string::npos || whatStr.size() == eqPos + 1) {
                LOG_S(ERROR) << "Error parsing \"what\" of ACI";
                throw Ldap::Exception(Ldap::ErrorCode::operationsError);
            }
            auto typeStr = whatStr.substr(0, eqPos);
            auto valStr = whatStr.substr(eqPos + 1);
            std::stringstream ss;
            if (typeStr.starts_with("dn")) {
                if (typeStr == "dn.exact" || typeStr == "dn.base") {
                    ss << "^" << valStr << "$";
                    scope = Scope::Base;
                } else if(typeStr == "dn.regex" || typeStr == "dn") {
                    scope = Scope::Regex;
                    ss << valStr;
                } else if(typeStr == "dn.one") {
                    scope = Scope::One;
                    ss << "^" << valStr << ",?[^,]+";
                } else if(typeStr == "dn.subtree") {
                    scope = Scope::Subtree;
                    ss << "^" << valStr << ",?.+";
                } else if(typeStr == "dn.children") {
                    scope = Scope::Children;
                    ss << "^" << valStr << ",.+";
                }
                dn = boost::regex{ ss.str() };
            }
            else if(typeStr == "filter") {
                filter = Ldap::parseFilter(valStr);
            }
            else if(typeStr == "attrs") {
                using commaTokenizer = boost::tokenizer<boost::escaped_list_separator<char>>;
                commaTokenizer valTok(valStr);
                for (auto valIt = valTok.begin(); valIt != valTok.end(); ++valIt) {
                    attrs.emplace(*valIt);
                }
            }
            else
                break;
        } while(it++ != tok.end());
    }

    do {
        controls.emplace_back(it, tok.end());
    } while(it != tok.end());
}

ACE::ACE(tokenizer::iterator& cur, const tokenizer::iterator end)
{
    if (cur == end) {
        LOG_S(ERROR) << "End of tokens while parsing ACE";
        throw Ldap::Exception(Ldap::ErrorCode::protocolError);
    }

    if (*cur++ != "by") {
        LOG_S(ERROR) << "access directive missing \"by\"";
        throw Ldap::Exception(Ldap::ErrorCode::protocolError);
    }

    boost::string_ref whatStr(*cur++);

    if (cur == end) {
        LOG_S(ERROR) << "ACE must consist of a <who> <access> [control] triplet - only found <who>";
        throw Ldap::Exception(Ldap::ErrorCode::protocolError);
    }

    // First we parse out the "who" part of the ACE
    auto eqPos = whatStr.find('=');
    boost::optional<boost::string_ref> valStr;
    boost::string_ref typeStr;
    if (eqPos != std::string::npos) {
        typeStr = whatStr.substr(0, eqPos);
        valStr = whatStr.substr(eqPos + 1);
    } else {
        typeStr = whatStr;
    }

    if (whatStr == "*")
        target = Target::All;
    else if (whatStr == "anonymous")
        target = Target::Anonymous;
    else if (whatStr == "users")
        target = Target::Users;
    else if (whatStr == "self")
        target = Target::Self;
    else if (typeStr.starts_with("dn")) {
        if (!valStr || valStr->length() == 0) {
            LOG_S(ERROR) << "Error parsing dn of \"who\" in ACI";
            throw Ldap::Exception(Ldap::ErrorCode::protocolError);
        }

        target = Target::Dn;
        std::stringstream ss;
        if (typeStr == "dn.exact" || typeStr == "dn.base") {
            ss << "^" << *valStr << "$";
            scope = Scope::Base;
        } else if(typeStr == "dn.regex" || typeStr == "dn") {
            ss << *valStr;
            scope = Scope::Regex;
        } else if(typeStr == "dn.one") {
            ss << "^" << *valStr << ",?[^,]+";
            scope = Scope::One;
        } else if(typeStr == "dn.subtree") {
            ss << "^" << *valStr << ",?.+";
            scope = Scope::Subtree;
        } else if(typeStr == "dn.children") {
            ss << "^" << *valStr << ",.+";
            scope = Scope::Children;
        }
        matchStr = boost::regex { ss.str() };
    }
    else if (typeStr == "dnattr") {
        target = Target::DnAttr;
        if (!valStr || valStr->size() == 0) {
            LOG_S(ERROR) << "Error parsing dnattr of \"who\" in ACI";
            throw Ldap::Exception(Ldap::ErrorCode::protocolError);
        }
        attrName = std::string{ *valStr };
    }
    else if (typeStr.starts_with("group")) {
        std::vector<std::string> groupParts;
        boost::split(groupParts, typeStr, boost::is_any_of("/"));
        if (groupParts.size() > 1) {
            attrName = groupParts[1];
        }
        groupDN = std::string{ *valStr };
    }

    // Next the "access" level part of the ACE
    boost::string_ref levelStr{ *cur++ };

    if (levelStr == "none")
        level = Level::None;
    else if(levelStr == "disclose")
        level = Level::Disclose;
    else if(levelStr == "auth")
        level = Level::Auth;
    else if(levelStr == "compare")
        level = Level::Compare;
    else if(levelStr == "search")
        level = Level::Search;
    else if(levelStr == "read")
        level = Level::Read;
    else if(levelStr == "write")
        level = Level::Write;
    else if(levelStr == "selfwrite")
        level = Level::SelfWrite;
    else if(levelStr == "manage")
        level = Level::Manage;

    if (cur != end) {
        bool advance = true;
        boost::string_ref controlStr { *cur };
        if (controlStr == "stop")
            control = Control::Stop;
        else if (controlStr == "continue")
            control = Control::Continue;
        else if (controlStr == "break")
            control = Control::Break;
        else
            advance = false;

        if (advance)
            cur++;
    }
}

namespace {
    std::vector<std::shared_ptr<Entry>> masterACLList;
    std::mutex masterACLListMutex;
} // anonymous namespace

void refreshThread(YAML::Node& config) {
    loguru::set_thread_name("acl thread");
    auto db = Storage::Mongo::MongoBackend{
        "mongodb://localhost",
        "directory",
        "rootdn",
        "accessControl"
    };

    int refreshPeriod = -1;
    if (config["aclRefreshPeriod"]) {
        refreshPeriod = config["aclRefreshPeriod"].as<int>();
    }
    std::chrono::seconds refreshPeriodDuration(refreshPeriod);

        for(;;) {
        std::lock_guard<std::mutex> lg(masterACLListMutex);
        masterACLList.clear();
        try {
            for (auto it = db.aceBegin(); it != db.aceEnd(); ++it) {
                masterACLList.push_back(std::make_shared<Entry>(*it));
            }
        } catch(std::exception & e) {
            LOG_S(ERROR) << "Error updating master ACL list: " << e.what();
        }

        LOG_S(INFO) << "Refreshed master ACL list. " << masterACLList.size() << " entries.";
        if (refreshPeriod > 0)
            std::this_thread::sleep_for(refreshPeriodDuration);
        else
            break;
    }
}

using EntryList = std::vector<std::shared_ptr<Entry>>;

EntryList getACLs(const Ldap::Entry& entry) {
    EntryList acls;
    std::lock_guard<std::mutex> lg(masterACLListMutex);
    for (auto && e: masterACLList) {
        if (e->scope != Scope::Nothing && boost::regex_match(entry.dn, e->dn))
            acls.emplace_back(e);
        else if(e->filter.type != Ldap::Filter::Type::None && e->filter.match(entry))
            acls.emplace_back(e);
        else if(e->attrs.size() > 0)
            acls.emplace_back(e);
    }
    return acls;
}

bool checkAccess(
    Storage::Mongo::MongoBackend& backend,
    const Ldap::Entry entry,
    const std::string forDN,
    const std::set<std::string> attrs,
    Level level)
{
    EntryList acls = getACLs(entry);
    for(auto && c: acls) {
        // If this is an ACL that only applies to attrs, make sure there's an intersection
        // between its list of attributes and ours.
        if (c->scope == Scope::Nothing &&
                c->filter.type == Ldap::Filter::Type::None &&
                attrs.size() > 0) {
            bool found = false;
            for (auto && intersectFind: attrs) {
                if (c->attrs.find(intersectFind) != c->attrs.end()) {
                    found = true;
                    break;
                }
            }
            if (!found)
                continue;
        }

        for (auto && ace: c->controls) {
            switch (ace.target) {
                case Target::Users:
                    if (forDN.empty())
                        continue;
                    break;
                case Target::Self:
                    if (forDN != entry.dn)
                        continue;
                    break;
                case Target::Dn:
                    if (boost::regex_match(forDN, ace.matchStr))
                        continue;
                    break;
                case Target::DnAttr: {
                    auto it = entry.attributes.find(ace.attrName);
                    if (it == entry.attributes.end())
                        continue;
                    bool found = false;
                    for (auto && attrCheck: it->second) {
                        if (attrCheck == forDN) {
                            found = true;
                            break;
                        }
                    }
                    if (!found)
                        continue;
                                          }
                    break;
                case Target::Group: {
                    auto groupEntry = backend.findEntry(ace.groupDN);
                    auto attrName = ace.attrName.empty() ? "member" : ace.attrName;
                    auto members = groupEntry->find(attrName);
                    if (!members)
                        continue;
                    bool found = false;
                    for (auto && m: *members) {
                        if (m == forDN) {
                            found = true;
                            break;
                        }
                    }
                    if (!found)
                        continue;
                                         }
                    break;
                default:
                    break;
            }
            if (ace.level >= level)
                return true;

            bool shouldContinue;
            switch(ace.control) {
                case Control::Stop:
                    return false;
                case Control::Break:
                    shouldContinue = false;
                    break;
                default:
                    shouldContinue = true;
            }
            if (!shouldContinue)
                break;
        }
    }
    return false;
}

} // namespace Access
} // namespace Ldap
