#include "exceptions.h"
#include "ldapproto.h"
#include "access.h"
#include "catch.hpp"

TEST_CASE("parse access", "[Entry]") {
    SECTION("read access to all") {
        auto e = Ldap::Access::Entry("to * by * read");
        REQUIRE(e.scope == Ldap::Access::Scope::All);
        REQUIRE(e.attrs.size() == 0);
        REQUIRE(e.controls.size() == 1);

        auto ace = e.controls[0];
        REQUIRE(ace.target == Ldap::Access::Target::All);
        REQUIRE(ace.level == Ldap::Access::Level::Read);
    }

    SECTION("self write, anonymous auth, all read") {
        auto e = Ldap::Access::Entry{
            "to * "
            "by self write "
            "by anonymous auth "
            "by * read"
        };
        REQUIRE(e.scope == Ldap::Access::Scope::All);
        REQUIRE(e.attrs.size() == 0);
        REQUIRE(e.controls.size() == 3);

        auto selfWrite = e.controls[0];
        REQUIRE(selfWrite.target == Ldap::Access::Target::Self);
        REQUIRE(selfWrite.level == Ldap::Access::Level::Write);

        auto anonymousAuth = e.controls[1];
        REQUIRE(anonymousAuth.target == Ldap::Access::Target::Anonymous);
        REQUIRE(anonymousAuth.level == Ldap::Access::Level::Auth);

        auto allRead = e.controls[2];
        REQUIRE(allRead.target == Ldap::Access::Target::All);
        REQUIRE(allRead.level == Ldap::Access::Level::Read);
    }
}
