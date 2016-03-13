#include "exceptions.h"
#include "ldapproto.h"
#include "catch.hpp"

TEST_CASE("parse filter", "[Filter]") {
    SECTION("present") {
        std::string filterStr = "(objectClass=*)";
        auto p = Ldap::parseFilter(filterStr);

        REQUIRE(p.type == Ldap::Filter::Type::Present);
        REQUIRE(p.attributeName == "objectClass");
    }
    SECTION("eq") {
        std::string filterStr = "(objectClass=person)";
        auto p = Ldap::parseFilter(filterStr);
        REQUIRE(p.type == Ldap::Filter::Type::Eq);
        REQUIRE(p.attributeName == "objectClass");
        REQUIRE(p.value == "person");
    }
    SECTION("lte") {
        std::string filterStr = "(uidNumber<=1000)";
        auto p = Ldap::parseFilter(filterStr);
        REQUIRE(p.type == Ldap::Filter::Type::Lte);
        REQUIRE(p.attributeName == "uidNumber");
        REQUIRE(p.value == "1000");
    }
    SECTION("sub-initial") {
        std::string filterStr = "(field=anyval*)";
        auto p = Ldap::parseFilter(filterStr);
        REQUIRE(p.type == Ldap::Filter::Type::Sub);
        REQUIRE(p.subChildren.size() == 1);
        REQUIRE(p.subChildren[0].type == Ldap::SubFilter::Type::Initial);
    }
    SECTION("sub-any") {
        std::string filterStr = "(field=*anyval*)";
        auto p = Ldap::parseFilter(filterStr);
        REQUIRE(p.type == Ldap::Filter::Type::Sub);
        REQUIRE(p.subChildren.size() == 1);
        REQUIRE(p.subChildren[0].type == Ldap::SubFilter::Type::Any);
    }
    SECTION("sub-final") {
        std::string filterStr = "(field=*anyval)";
        auto p = Ldap::parseFilter(filterStr);
        REQUIRE(p.type == Ldap::Filter::Type::Sub);
        REQUIRE(p.subChildren.size() == 1);
        REQUIRE(p.subChildren[0].type == Ldap::SubFilter::Type::Final);
    }
    SECTION("sub-initial-any-any-final") {
        std::string filterStr = "(field=first*second*third*fourth)";
        auto p = Ldap::parseFilter(filterStr);
        REQUIRE(p.type == Ldap::Filter::Type::Sub);
        REQUIRE(p.subChildren.size() == 4);
        REQUIRE(p.subChildren[0].type == Ldap::SubFilter::Type::Initial);
        REQUIRE(p.subChildren[0].value == "first");
        REQUIRE(p.subChildren[1].type == Ldap::SubFilter::Type::Any);
        REQUIRE(p.subChildren[1].value == "second");
        REQUIRE(p.subChildren[2].type == Ldap::SubFilter::Type::Any);
        REQUIRE(p.subChildren[2].value == "third");
        REQUIRE(p.subChildren[3].type == Ldap::SubFilter::Type::Final);
        REQUIRE(p.subChildren[3].value == "fourth");
    }
    SECTION("sub-initial-any-final") {
        std::string filterStr = "(field=first*second*third)";
        auto p = Ldap::parseFilter(filterStr);
        REQUIRE(p.type == Ldap::Filter::Type::Sub);
        REQUIRE(p.subChildren[0].type == Ldap::SubFilter::Type::Initial);
        REQUIRE(p.subChildren[1].type == Ldap::SubFilter::Type::Any);
        REQUIRE(p.subChildren[2].type == Ldap::SubFilter::Type::Final);
    }
    SECTION("sub-any-final") {
        std::string filterStr = "(field=*first*second)";
        auto p = Ldap::parseFilter(filterStr);
        REQUIRE(p.type == Ldap::Filter::Type::Sub);
        REQUIRE(p.subChildren[0].type == Ldap::SubFilter::Type::Any);
        REQUIRE(p.subChildren[1].type == Ldap::SubFilter::Type::Final);
    }
    SECTION("sub-intiial-final") {
        std::string filterStr = "(field=first*second)";
        auto p = Ldap::parseFilter(filterStr);
        REQUIRE(p.type == Ldap::Filter::Type::Sub);
        REQUIRE(p.subChildren[0].type == Ldap::SubFilter::Type::Initial);
        REQUIRE(p.subChildren[1].type == Ldap::SubFilter::Type::Final);
    }
    SECTION("and") {
        std::string filterStr = "(&(objectClass=*)(field=first*second*third))";
        auto p = Ldap::parseFilter(filterStr);
        REQUIRE(p.type == Ldap::Filter::Type::And);
        REQUIRE(p.children.size() == 2);
        REQUIRE(p.children[0].type == Ldap::Filter::Type::Present);
        REQUIRE(p.children[0].attributeName == "objectClass");
        REQUIRE(p.children[1].type == Ldap::Filter::Type::Sub);
        REQUIRE(p.children[1].subChildren.size() == 3);
    }
    SECTION("or") {
        std::string filterStr = "(&(objectClass=*)(foo=bar))";
        auto p = Ldap::parseFilter(filterStr);
        REQUIRE(p.type == Ldap::Filter::Type::And);
        REQUIRE(p.children.size() == 2);
        REQUIRE(p.children[0].type == Ldap::Filter::Type::Present);
        REQUIRE(p.children[0].attributeName == "objectClass");
        REQUIRE(p.children[1].type == Ldap::Filter::Type::Eq);
        REQUIRE(p.children[1].attributeName == "foo");
        REQUIRE(p.children[1].value == "bar");
    }
}
