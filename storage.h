#include <iterator>
#include <memory>
#include <string>

#include <mongocxx/client.hpp>

namespace Storage {

namespace Mongo {
class MongoCursor {
public:
    class iterator;

    MongoCursor(MongoCursor&&) noexcept = default;
    MongoCursor& operator=(MongoCursor&&) noexcept = default;
    ~MongoCursor() {};

    iterator begin();
    iterator end();
private:
    friend class MongoBackend;
    MongoCursor(mongocxx::cursor curs) :
        _cursor { std::move(curs) }
    { };

    mongocxx::cursor _cursor;
};

class MongoCursor::iterator : public std::iterator<std::input_iterator_tag, Ldap::Entry>
{
public:
    ~iterator() { };
    const Ldap::Entry& operator*() { refreshDocument(); return curEntry; };
    const Ldap::Entry* operator->() { refreshDocument(); return &curEntry; };
    iterator& operator++();
    void operator++(int) { operator++(); };

    bool operator==(const iterator& rhs) {
        return _cursorIt == rhs._cursorIt;
    }
    bool operator!=(const iterator& rhs) {
        return _cursorIt != rhs._cursorIt;
    }

private:
    friend class MongoCursor;

    void refreshDocument();
 
    explicit iterator(mongocxx::cursor::iterator curs) :
        _cursorIt { std::move(curs) }
    {};

    mongocxx::cursor::iterator _cursorIt;
    Ldap::Entry curEntry;
};

class MongoBackend {
public:
    MongoBackend(
        std::string connectURI,
        std::string db,
        std::string collection,
        std::string rootDN
    );
    ~MongoBackend() {};

    MongoBackend(const MongoBackend&) = default;
    MongoBackend(MongoBackend&&) = default;

    void saveEntry(Ldap::Entry e);
    std::unique_ptr<Ldap::Entry> findEntry(std::string dn);
    std::unique_ptr<MongoCursor> findEntries(Ldap::Search::Request req);
    void deleteEntry(std::string dn);

private:

    mongocxx::client _client;
    mongocxx::collection _collection;
    std::string _rootdn;

};


} // namespace Mongo
} // namespace Storage
