#include <string>
#include <vector>
#include <memory>
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

struct ACE {
    enum class Target {
        Nobody,
        All,
        Anonymous,
        Users,
        Self,
        Dn,
        DnAttr,
        Group,
    } target = Target::Nobody;

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
    } level = Level::None;

    enum class Control {
        Stop,
        Continue,
        Break
    } control = Control::Break;

    Scope scope = Scope::Nothing;

    boost::regex matchStr;
    std::string groupObjectClass;
    std::string attrName;
    ACE(tokenizer::iterator& cur, const tokenizer::iterator end);
};


struct Entry {
    Ldap::Filter filter;
    boost::regex dn;
    Scope scope = Scope::Nothing;
    std::vector<std::string> attrs;

    std::vector<ACE> controls;

    Entry(const std::string& str);
};

using EntryList = std::vector<std::weak_ptr<Entry>>;

void refreshThread(YAML::Node& config);
EntryList getACLFor(std::string dn, std::string filter);

} // namespace Access
} // namespace Ldap
