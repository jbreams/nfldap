#include <string>
#include <vector>
#include <memory>
#include <set>
#include <tuple>

#include <boost/tokenizer.hpp>
#include <boost/regex.hpp>

#include <yaml-cpp/yaml.h>

namespace Ldap {
namespace Access {

using tokenizer = boost::tokenizer<boost::char_separator<char>>;

enum class Scope {
    Nothing,
    All,
    Base,
    One,
    Subtree,
    Children,
    Regex
};

enum class Level {
    None,
    Disclose,
    Auth,
    Compare,
    Search,
    Read,
    SelfWrite,
    Write,
    Manage
};

enum class Target {
    Nobody,
    All,
    Anonymous,
    Users,
    Self,
    Dn,
    DnAttr,
    Group,
};

enum class Control {
    Stop,
    Continue,
    Break
};

struct ACE {
    Target target = Target::Nobody;
    Level level = Level::None;
    Control control = Control::Break;

    Scope scope = Scope::Nothing;

    boost::regex matchStr;
    std::string groupDN;
    std::string attrName;
    ACE(tokenizer::iterator& cur, const tokenizer::iterator end);
};


struct Entry {
    Ldap::Filter filter;
    boost::regex dn;
    Scope scope = Scope::Nothing;
    std::set<std::string> attrs;

    std::vector<ACE> controls;

    Entry(const std::string& str);
};

void refreshThread(YAML::Node& config);

} // namespace Access
} // namespace Ldap
