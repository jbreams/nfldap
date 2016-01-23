#include <ctime>
#include <iostream>
#include <string>
#include <thread>
#include <asio.hpp>
#include <cctype>
#include <utility>

#include <pthread.h>

#include "loguru.hpp"
#include "exceptions.h"
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
    std::stringstream threadName;
    threadName << sock.remote_endpoint();
    loguru::set_thread_name(threadName.str().c_str());
    auto db = Storage::Mongo::MongoBackend{
        "mongodb://localhost",
        "directory",
        "rootdn",
        "dc=mongodb,dc=com"
    };

    for (;;)
    {
        std::vector<uint8_t> header(2);;
        size_t length;
        asio::error_code error;

        length = sock.read_some(asio::buffer(header), error);
        if (error) {
            if (error == asio::error::eof)
                break;
            else
                throw asio::system_error(error);
        }
        if (length != header.size()) {
            LOG_F(ERROR, "Client sent malformed BER header");
            break;
        }

        std::vector<uint8_t> reqBuffer;
        reqBuffer.reserve(1024);
        if ((header[1] & 128) != 0) {
            header[1] -= 128;
            reqBuffer.resize(header[1]);
            length = sock.read_some(asio::buffer(reqBuffer), error);
            if (length != reqBuffer.size()) {
                LOG_F(ERROR, "Client sent mal-formed BER size header");
                break;
            }
            auto decodedReqSize = Ber::decodeInteger(reqBuffer.cbegin(), reqBuffer.cend());
            reqBuffer.resize(decodedReqSize, 0);
        } else {
            reqBuffer.resize(header[1], 0);
        }
        length = sock.read_some(asio::buffer(reqBuffer), error);
        if (length != reqBuffer.size()) {
            LOG_F(ERROR, "Client sent fewer bytes than expected");
            break;
        }

        auto ber = Ber::Packet::decode(header[0], reqBuffer);
        auto messageId = static_cast<uint64_t>(ber.children[0]);
        auto messageType = Ldap::MessageTag { static_cast<Ldap::MessageTag>(ber.children[1].tag) };

        Ldap::MessageTag errorResponseType;
        switch (messageType) {
        case Ldap::MessageTag::SearchRequest:
            errorResponseType = Ldap::MessageTag::SearchResDone;
            break;
        default:
            errorResponseType = static_cast<Ldap::MessageTag>(static_cast<uint8_t>(messageType) + 1);
            break;
        }
        try {
            if (messageType == Ldap::MessageTag::BindRequest) {
                Ldap::Bind::Request bindReq(ber.children[1]);

                Ldap::Bind::Response bindResp(Ldap::buildLdapResult(0, bindReq.dn, "",
                            Ldap::MessageTag::BindResponse));
                sendResponse(sock, messageId, bindResp.response);
            }
            else if (messageType == Ldap::MessageTag::SearchRequest) {
                Ldap::Search::Request searchReq(ber.children[1]);
                auto cursor = db.findEntries(searchReq);

                for (auto && entry: *cursor) {
                    sendResponse(sock, messageId, Ldap::Search::generateResult(entry));
                }

                sendResponse(sock, messageId,
                    Ldap::buildLdapResult(0, "", "", Ldap::MessageTag::SearchResDone));
            }
            else if (messageType == Ldap::MessageTag::AddRequest) {
                Ldap::Entry entry = Ldap::Add::parseRequest(ber.children[1]);
                db.saveEntry(entry, true);
                sendResponse(sock, messageId,
                    Ldap::buildLdapResult(0, "", "", Ldap::MessageTag::AddResponse));
            }
            else if (messageType == Ldap::MessageTag::DelRequest) {
                std::string dn = Ldap::Delete::parseRequest(ber.children[1]);
                db.deleteEntry(dn);
                sendResponse(sock, messageId,
                    Ldap::buildLdapResult(0, "", "", Ldap::MessageTag::DelResponse));
            }
        } catch (const Ldap::Exception& e) {
            auto resPacket = Ldap::buildLdapResult(e, "", e.what(), errorResponseType);
            sendResponse(sock, messageId, resPacket);
            break;
        } catch (const std::exception& e) {
            auto resPacket = Ldap::buildLdapResult(static_cast<int>(Ldap::ErrorCode::other),
                "", e.what(), errorResponseType);
            sendResponse(sock, messageId, resPacket);
            break;
        } catch (...) {
            auto resPacket = Ldap::buildLdapResult(static_cast<int>(Ldap::ErrorCode::other),
                "", "Unknown error occurred", errorResponseType);
            sendResponse(sock, messageId, resPacket);
            break;
        }
    }
}

int main(int argc, char** argv)
{
    loguru::init(argc, argv);
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
