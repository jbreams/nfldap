#include <ctime>
#include <iostream>
#include <string>
#include <thread>
#include <asio.hpp>
#include <cctype>
#include <utility>

#include "ldapproto.h"
#include "storage.h"

using asio::ip::tcp;

void sendResponse(tcp::socket& sock, uint64_t messageId, Ber::Packet response) {
    Ber::Packet envelope(
        Ber::Type::Constructed, Ber::Class::Universal, Ber::Tag::Sequence);
    envelope.appendChild(Ber::Packet(Ber::Tag::Integer, messageId));
    envelope.appendChild(response);

    std::vector<uint8_t> bytes;
    bytes.reserve(envelope.length());
    envelope.copyBytes(bytes);
    sock.send(asio::buffer(bytes));
}

void session_thread(tcp::socket sock) {
    auto db = Storage::Mongo::MongoBackend{
        "mongodb://localhost",
        "directory",
        "rootdn",
        "dc=mongodb,dc=com"
    };

    for (;;)
    {
        std::vector<uint8_t> reqBuffer(1024);
        asio::error_code error;
        size_t length = sock.read_some(asio::buffer(reqBuffer), error);
        if (error == asio::error::eof) {
            std::cout << "peer closed the connection" << std::endl;
            break; // Connection closed cleanly by peer.
        } else if (error)
            throw asio::system_error(error); // Some other error.
        else if (length == 0)
            continue;

        auto reqIt = reqBuffer.begin();
        auto ber = Ber::Packet::decode(reqIt, reqIt + length);
        auto messageId = static_cast<uint64_t>(ber.children[0]);
        auto messageType = Ldap::MessageTag { static_cast<Ldap::MessageTag>(ber.children[1].tag) };

        std::cout << "msg id: " << messageId << std::endl
                  << "message type: " << static_cast<uint8_t>(messageType) << std::endl;

        if (messageType == Ldap::MessageTag::BindRequest) {
            Ldap::Bind::Request bindReq(ber.children[1]);

            Ldap::Bind::Response bindResp(Ldap::buildLdapResult(0, bindReq.dn, "",
                        Ldap::MessageTag::BindResponse));
            sendResponse(sock, messageId, bindResp.response);
        }
        else if(messageType == Ldap::MessageTag::SearchRequest) {
            Ldap::Search::Request searchReq(ber.children[1]);
            auto cursor = db.findEntries(searchReq);

            for (auto && entry: *cursor) {
                std::cout << "Sending result for " << entry.dn << std::endl;
                sendResponse(sock, messageId, Ldap::Search::generateResult(entry));
            }

            sendResponse(sock, messageId,
                Ldap::buildLdapResult(0, "", "", Ldap::MessageTag::SearchResDone));
        }
        else if(messageType == Ldap::MessageTag::AddRequest) {
            Ldap::Entry entry = Ldap::Add::parseRequest(ber.children[1]);
            db.saveEntry(entry);
            sendResponse(sock, messageId,
                Ldap::buildLdapResult(0, "", "", Ldap::MessageTag::AddResponse));
        }
        else if(messageType == Ldap::MessageTag::DelRequest) {
            std::string dn = Ldap::Delete::parseRequest(ber.children[1]);
            db.deleteEntry(dn);
            sendResponse(sock, messageId,
                Ldap::buildLdapResult(0, "", "", Ldap::MessageTag::DelResponse));
        }
    }
}

int main()
{
    try
    {
        asio::io_service io_service;

        tcp::acceptor acceptor(io_service, tcp::endpoint(tcp::v4(), 3890));

        for (;;)
        {
            tcp::socket socket(io_service);
            acceptor.accept(socket);

            std::thread(session_thread, std::move(socket)).detach();
        }
    }
    catch (std::exception& e)
    {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
