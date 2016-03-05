#include <cctype>
#include <regex>
#include <algorithm>

#include <boost/tokenizer.hpp>
#include <boost/regex.hpp>

#include "exceptions.h"
#include "ldapproto.h"

namespace Ldap {

namespace {
using tokenizer = boost::tokenizer<boost::char_separator<char>>;

inline void skipWhitespace(boost::string_ref::iterator& it, const boost::string_ref::iterator end) {
    while(it != end && std::isspace(*it))
        it++;
}

inline void findRightParen(boost::string_ref::iterator& it, const boost::string_ref::iterator end) {
    int balance = 1;
    bool escape = false;

    while (it != end && balance) {
        if (!escape) {
            if (*it == '(') {
                balance++;
            }
            else if (*it == ')') {
                balance--;
            }
        }

        escape = (*it == '\\' && !escape);
        if (balance) {
            it++;
        }
    }
}

} // anonymous namespace

std::vector<Filter> parseFilterList(
        boost::string_ref p,
        boost::string_ref::iterator start,
        const boost::string_ref::iterator end)
{
    std::vector<Filter> filterList;
    auto curStart = start;
    curStart++;
    while (curStart != end) {
        auto curEnd = curStart;
        findRightParen(curEnd, end);
        boost::string_ref subFilter = p.substr(curStart - p.begin(), curEnd - curStart);
        filterList.push_back(parseFilter(subFilter));
        curStart = curEnd;
        curStart++;
    }

    std::stable_sort(filterList.begin(), filterList.end());
    return filterList;
}

Filter parseFilter(boost::string_ref p) {
    auto it = p.begin();
    auto end = p.end();
    skipWhitespace(it, end);

    if (*it++ != '(') {
        throw Ldap::Exception(Ldap::ErrorCode::protocolError,
                "Search filter does not begin with (");
    }

    auto rightParen = it;
    findRightParen(rightParen, end);
    if (rightParen == end) {
        throw Ldap::Exception(Ldap::ErrorCode::protocolError,
                "Search filter's parentheses aren't balanced");
    }

    std::vector<Filter> filterList;

    if (*it == '&') {
        return Filter { Filter::Type::And, parseFilterList(p, it, end) };
    }
    else if(*it == '|') {
        return Filter { Filter::Type::Or, parseFilterList(p, it, end) };
    }
    else if(*it == '!') {
        return Filter { Filter::Type::Not, parseFilterList(p, it, end) };
    }

    // handle the general case - this is a normal equality filter or substring filter
    auto eqPos = p.find('=');
    if (eqPos == std::string::npos || eqPos == 0) {
        throw Ldap::Exception(Ldap::ErrorCode::protocolError,
                "Search filter is missing or has invalid attribute name");
    }

    boost::string_ref attrName = p.substr(0, eqPos);
    boost::string_ref valPart = p.substr(eqPos + 1);

    if (valPart == "*") {
        return Filter { Filter::Type::Present, std::string{ attrName }};
    }

    if (valPart.find("*") == std::string::npos) {
        auto qualifier = p[eqPos - 1];
        auto type = Filter::Type::Eq;
        if (qualifier == '~') {
            type = Filter::Type::Approx;
        }
        else if(qualifier == '<') {
            type = Filter::Type::Lte;
        }
        else if(qualifier == '>') {
            type = Filter::Type::Gte;
        }

        if (type != Filter::Type::Eq) {
            attrName.remove_suffix(1);
        }
        return Filter { Filter::Type::Eq, std::string{ attrName }, std::string{ valPart } };
    }

    std::vector<SubFilter> subMatches;
    boost::char_separator<char> starSep("*");
    tokenizer tokens(valPart, starSep);
    for (auto p: tokens) {
        subMatches.emplace_back(SubFilter::Type::Any, std::string{p});
    }
    if (subMatches.size() > 1) {
        subMatches[0].type = SubFilter::Type::Initial;
    }
    if (subMatches.size() > 2) {
        subMatches[subMatches.size() - 1].type = SubFilter::Type::Final;
    }

    return Filter { std::string{ attrName }, std::move(subMatches) };

}

Filter parseFilter(const std::string& p) {
    return parseFilter(boost::string_ref{p});
}

bool Filter::match(const Entry& e) {
    switch(type) {
        case Type::And:
            for (auto && c: children) {
                if (c.match(e) == false)
                    return false;
            }
            return true;
        case Type::Or:
            for (auto && c: children) {
                if (c.match(e) == true)
                    return true;
            }
            return false;
        case Type::Not:
            return !children[0].match(e);
        case Type::Eq:
        case Type::Gte:
        case Type::Lte:
        case Type::Sub:
                       {
            auto foundAttrVals = e.attributes.find(attributeName);
            if (foundAttrVals == e.attributes.end())
               return false;
            boost::regex subMatcher;
            if (type == Type::Sub) {
                std::stringstream ss;
                for (auto && c: subChildren) {
                    switch(c.type) {
                        case SubFilter::Type::Initial:
                            ss << "^" << c.value;
                            break;
                        case SubFilter::Type::Final:
                            ss << ".+" << c.value << "$";
                            break;
                        case SubFilter::Type::Any:
                            ss << ".+" << c.value;
                            break;
                    }
                }
                subMatcher = boost::regex { ss.str() };
            }

            for (auto && c: foundAttrVals->second) {
                if (type == Type::Eq && c == value)
                    return true;
                else if(type == Type::Gte && value >= c)
                    return true;
                else if(type == Type::Lte && value <= c)
                    return true;
                else if(type == Type::Sub && boost::regex_match(c, subMatcher))
                    return true;
            }
            return false;
                       }
        case Type::Present:
            return (e.attributes.find(attributeName) != e.attributes.end());
        case Type::Approx:
        case Type::Extensible:
            throw Ldap::Exception(Ldap::ErrorCode::other, "Filter type not supported");
        default:
            return false;
    }
    return false;
}

bool operator<(const SubFilter lhs, const SubFilter rhs) {
    return (lhs.type < rhs.type && lhs.value < rhs.value);
}

bool operator==(const SubFilter lhs, const SubFilter rhs) {
    return (lhs.type == rhs.type && lhs.value == rhs.value);
}

bool operator<(const Filter lhs, const Filter rhs) {
   if (lhs.type != rhs.type)
       return false;

   switch(lhs.type) {
       case Filter::Type::And:
       case Filter::Type::Or:
       case Filter::Type::Not:
           return (lhs.children < rhs.children);
       case Filter::Type::Eq:
       case Filter::Type::Gte:
       case Filter::Type::Lte:
           return (lhs.attributeName < rhs.attributeName && lhs.value < rhs.value);
       case Filter::Type::Sub:
           return (lhs.attributeName < rhs.attributeName && lhs.subChildren < rhs.subChildren);
       case Filter::Type::Present:
           return (lhs.attributeName < rhs.attributeName);
       default:
           return false;
   }
}

bool operator==(const Filter lhs, const Filter rhs) {
   if (lhs.type != rhs.type)
       return false;

   switch(lhs.type) {
       case Filter::Type::And:
       case Filter::Type::Or:
       case Filter::Type::Not:
           return (lhs.children == rhs.children);
       case Filter::Type::Eq:
       case Filter::Type::Gte:
       case Filter::Type::Lte:
           return (lhs.attributeName == rhs.attributeName && lhs.value == rhs.value);
       case Filter::Type::Sub:
           return (lhs.attributeName == rhs.attributeName && lhs.subChildren == rhs.subChildren);
       case Filter::Type::Present:
           return (lhs.attributeName == rhs.attributeName);
       default:
           return false;
   }
}

} // namespace Ldap
