#include <ctime>
#include <iostream>
#include <string>
#include <thread>
#include <asio.hpp>
#include <cctype>
#include <utility>
#include <set>

#include <yaml-cpp/yaml.h>
#include <pthread.h>

#include "loguru.hpp"
#include "exceptions.h"
#include "ldapproto.h"
#include "storage.h"
#include "passwords.h"

using asio::ip::tcp;
YAML::Node config;

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

    bool noAuthentication = false;
    // Put this into its own scope so the YAML nodes get cleaned up.
    {
        auto check = config["noAuthentication"];
        if (check && check.as<bool>() == true)
            noAuthentication = true;
    }

    bool userBound = false;
    std::string userBoundDN;

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
                if (bindReq.type == Ldap::Bind::Request::Type::Sasl) {
                // TODO SUPPORT SASL BINDS!
                    throw Ldap::Exception(Ldap::ErrorCode::authMethodNotSupported);
                }

                bool passOkay = false;
                if (noAuthentication) {
                    LOG_S(INFO)
                        << "Authentication is disabled, sending bogus bind for "
                        << bindReq.dn;
                    passOkay = true;
                } else {
                    LOG_S(INFO) << "Authenticating " << bindReq.dn;
                    try {
                        auto entry = db.findEntry(bindReq.dn);
                        for (const auto& pass: entry->attributes.at("userPassword")) {
                            passOkay = Password::checkPassword(bindReq.simple, pass);
                            if (passOkay)
                                break;
                        }

                    } catch (Ldap::Exception e) {
                        LOG_S(ERROR) << "Error during authentication " << e.what();
                        if (e == Ldap::ErrorCode::noSuchObject) {
                            throw Ldap::Exception(Ldap::ErrorCode::invalidCredentials);
                        }
                        throw;
                    }
                }

                Ldap::ErrorCode respCode;
                if (passOkay) {
                    respCode = Ldap::ErrorCode::success;
                    userBound = true;
                    userBoundDN = bindReq.dn;
                } else {
                    respCode = Ldap::ErrorCode::invalidCredentials;
                    userBound = false;
                    userBoundDN = "";
                }

                Ldap::Bind::Response bindResp(Ldap::buildLdapResult(respCode, bindReq.dn, "",
                            Ldap::MessageTag::BindResponse));
                sendResponse(sock, messageId, bindResp.response);
            }
            else if (messageType == Ldap::MessageTag::SearchRequest) {
                Ldap::Search::Request searchReq(ber.children[1]);
                auto cursor = db.findEntries(searchReq);

                for (const auto& entry: *cursor) {
                    sendResponse(sock, messageId, Ldap::Search::generateResult(entry));
                }

                sendResponse(sock, messageId,
                    Ldap::buildLdapResult(Ldap::ErrorCode::success,
                        "", "", Ldap::MessageTag::SearchResDone));
            }
            else if (messageType == Ldap::MessageTag::AddRequest) {
                Ldap::Entry entry = Ldap::Add::parseRequest(ber.children[1]);
                db.saveEntry(entry, true);
                sendResponse(sock, messageId,
                    Ldap::buildLdapResult(Ldap::ErrorCode::success,
                        "", "", Ldap::MessageTag::AddResponse));
            }
            else if (messageType == Ldap::MessageTag::ModifyRequest) {
                Ldap::Modify::Request req(ber.children[1]);
                auto entry = db.findEntry(req.dn);
                if (entry == nullptr) {
                    throw Ldap::Exception(Ldap::ErrorCode::noSuchObject);
                }
                for (const auto& mod: req.mods) {
                    using ModType = Ldap::Modify::Modification::Type;
                    switch(mod.type) {
                    case ModType::Add:
                        for (const auto& v: mod.values) {
                            entry->appendValue(mod.name, v);
                        }
                        break;
                    case ModType::Delete:
                        if (mod.values.size() == 0) {
                            if (entry->attributes.erase(mod.name) == 0) {
                                throw Ldap::Exception(Ldap::ErrorCode::noSuchAttribute);
                            }
                        } else {
                            try {
                                auto curVals = entry->attributes.at(mod.name);
                                std::set<std::string> finalVals(curVals.begin(), curVals.end());
                                for (const auto& v: mod.values) {
                                    if (finalVals.erase(v) == 0) {
                                        throw Ldap::Exception(Ldap::ErrorCode::noSuchAttribute);
                                    }
                                }
                                curVals.clear();
                                std::copy(finalVals.begin(), finalVals.end(),
                                    std::back_inserter(curVals));
                            } catch(std::out_of_range) {
                                throw Ldap::Exception(Ldap::ErrorCode::noSuchAttribute);
                            }
                        }
                        break;
                    case ModType::Replace:
                        if (mod.values.size() == 0) {
                            entry->attributes.erase(mod.name);
                        } else {
                            entry->attributes[mod.name] = mod.values;
                        }
                        break;
                    }
                }
                db.saveEntry(*entry, false);
                sendResponse(sock, messageId,
                    Ldap::buildLdapResult(Ldap::ErrorCode::success,
                        "", "", Ldap::MessageTag::ModifyResponse));
            }
            else if (messageType == Ldap::MessageTag::DelRequest) {
                std::string dn = Ldap::Delete::parseRequest(ber.children[1]);
                db.deleteEntry(dn);
                sendResponse(sock, messageId,
                    Ldap::buildLdapResult(Ldap::ErrorCode::success,
                        "", "", Ldap::MessageTag::DelResponse));
            }
        } catch (const Ldap::Exception& e) {
            auto resPacket = Ldap::buildLdapResult(e, "", e.what(), errorResponseType);
            sendResponse(sock, messageId, resPacket);
            break;
        } catch (const std::exception& e) {
            auto resPacket = Ldap::buildLdapResult(Ldap::ErrorCode::other,
                "", e.what(), errorResponseType);
            sendResponse(sock, messageId, resPacket);
            break;
        } catch (...) {
            auto resPacket = Ldap::buildLdapResult(Ldap::ErrorCode::other,
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
        config = YAML::LoadFile(argv[1]);
        asio::io_service io_service;

        int port = 3890;
        if (config["port"]) {
            port = config["port"].as<int>();
        }
        tcp::acceptor acceptor(io_service, tcp::endpoint(tcp::v4(), port));

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
