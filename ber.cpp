#include <algorithm>
#include <map>
#include <iostream>
#include <iomanip>

#include "loguru.hpp"

#include "ber.h"
#include "exceptions.h"

namespace Ber {

static std::map<Tag,std::string> tagToString = {
	{ Tag::EOC,              "EOC (End-of-Content)" },
	{ Tag::Boolean,          "Boolean" },
	{ Tag::Integer,          "Integer" },
	{ Tag::BitString,        "Bit String" },
	{ Tag::OctetString,      "Octet String" },
	{ Tag::NullValue,        "NULL" },
	{ Tag::ObjectIdentifier, "Object Identifier" },
	{ Tag::ObjectDescriptor, "Object Descriptor" },
	{ Tag::External,         "External" },
	{ Tag::RealFloat,        "Real (float)" },
	{ Tag::Enumerated,       "Enumerated" },
	{ Tag::EmbeddedPDV,      "Embedded PDV" },
	{ Tag::UTF8String,       "UTF8 String" },
	{ Tag::RelativeOID,      "Relative-OID" },
	{ Tag::Sequence,         "Sequence and Sequence of" },
	{ Tag::Set,              "Set and Set OF" },
	{ Tag::NumericString,    "Numeric String" },
	{ Tag::PrintableString,  "Printable String" },
	{ Tag::T61String,        "T61 String" },
	{ Tag::VideotexString,   "Videotex String" },
	{ Tag::IA5String,        "IA5 String" },
	{ Tag::UTCTime,          "UTC Time" },
	{ Tag::GeneralizedTime,  "Generalized Time" },
	{ Tag::GraphicString,    "Graphic String" },
	{ Tag::VisibleString,    "Visible String" },
	{ Tag::GeneralString,    "General String" },
	{ Tag::UniversalString,  "Universal String" },
	{ Tag::CharacterString,  "Character String" },
	{ Tag::BMPString,        "BMP String" }
};

static std::map<Class,std::string> classToString = {
	{ Class::Universal,   "Universal" },
	{ Class::Application, "Application" },
	{ Class::Context,     "Context" },
	{ Class::Private,     "Private" }
};

static std::map<Type,std::string> typeToString = {
	{ Type::Primative,    "Primative" },
	{ Type::Constructed,  "Constructed" }
};

uint64_t decodeInteger(ByteVectorCit begin, ByteVectorCit end) {
    uint64_t ret = 0;
    for (;begin != end; begin++) {
        ret *= 256;
        ret += *begin;
    }
    return ret;
}

Packet::Packet(Type _type, Class _class, uint8_t _tag):
   type{_type},
   berClass{_class},
   tag{_tag},
   data{},
   children{}
{
    children.reserve(2);
}

Packet::Packet(Type _type, Class _class, uint8_t _tag, std::string _value):
    Packet(_type, _class, _tag)
{
    std::copy(_value.begin(), _value.end(), std::back_inserter(data));
}

Packet::Packet(Type _type, Class _class, uint8_t _tag, uint64_t _value):
    Packet(_type, _class, _tag)
{
    encodeInteger(_value, data);
}

Packet::Packet(Type _type, Class _class, uint8_t _tag, bool _value):
    Packet(_type, _class, _tag)
{
    encodeInteger(_value ? 0 : 0xff, data);
}

Packet::Packet(Type _type, Class _class, uint8_t _tag, ByteVectorIt start, ByteVectorIt end):
    Packet(_type, _class, _tag)
{
    std::copy(start, end, std::back_inserter(data));
}

void encodeInteger(int64_t val, ByteVector& out) {
    out.reserve(sizeof(uint64_t));
    uint8_t sign = 0;
    uint64_t uintVal = val;

    if (val < 0) {
        sign = 0xff;
        uintVal = ~uintVal;
    }

    std::vector<uint8_t> tmpOut(sizeof(val));
    auto curPos = tmpOut.end() - 1;
    for (;curPos >= tmpOut.begin(); uintVal >>= 8) {
        *curPos-- = ((sign ^ static_cast<uint8_t>(uintVal)) & 0xff);
        if (uintVal < 0x80)
            break;
    }
    std::copy(curPos + 1, tmpOut.end(), std::back_inserter(out));
}

size_t Packet::length() {
    size_t ret = data.size() + 2;

    for (auto && c: children) {
        auto childLen = c.length();
        if (childLen > 127) {
            for (size_t uintChildLen = childLen; ; uintChildLen >>= 8) {
                childLen++;
                if (uintChildLen < 0x80)
                    break;
            }
        }
        ret += childLen;
    }

    return ret;
}

void Packet::copyBytes(ByteVector& out, bool topLevel) {
    const auto len = length();
    if (topLevel)
        out.reserve(len);

    uint8_t metaByte = static_cast<uint8_t>(type);
    metaByte |= static_cast<uint8_t>(berClass);
    metaByte |= static_cast<uint8_t>(tag);
    out.push_back(metaByte);

    ByteVector packetLen;
    encodeInteger(len - 2, packetLen);
    if (len > 127 || packetLen.size() > 1) {
        out.push_back(static_cast<uint8_t>(packetLen.size() | 128));
    }

    std::copy(packetLen.begin(), packetLen.end(), std::back_inserter(out));
    std::copy(data.begin(), data.end(), std::back_inserter(out));
    for (auto && c: children) {
        c.copyBytes(out, false);
    }
}

void Packet::appendChild(Packet p) {
    children.push_back(p);
}

void Packet::print(int indent) {
    std::string indentStr("  ", indent);
    std::cout << indentStr << "Type: " << typeToString[type] << " "
        << indentStr << "Class: " << classToString[berClass] << " "
        << indentStr << "Tag: " << tag << " ";
    Tag eTag = Tag::EOC;
    if (berClass == Class::Universal && tag < static_cast<uint8_t>(Tag::Bitmask)) {
        eTag = static_cast<Tag>(tag);
        std::cout << "(" << tagToString[eTag] << ") ";
    }
    std::cout << indentStr << "Packet length: " << length() << std::endl;
    if (type == Type::Primative && berClass == Class::Universal) {
        switch(eTag) {
        case Tag::Integer:
        case Tag::Enumerated:
            std::cout << indentStr << "Integer value: " << static_cast<uint64_t>(*this);
            break;
        case Tag::OctetString:
            std::cout << indentStr << "String value: " << static_cast<std::string>(*this);
            break;
        case Tag::Boolean:
            std::cout << indentStr << "Boolean value: " << static_cast<bool>(*this);
            break;
        default:
            std::cout << indentStr << "Byte array of " << data.size() << " bytes";
            std::cout << std::endl << indentStr;
            for (auto c: data) {
                std::cout << std::hex << c << " ";
            }
            std::cout << std::dec;
            break;
        }
        std::cout << std::endl;
    } else if (data.size() > 0) {
        std::cout << indentStr << "Byte array of " << data.size() << " bytes" << std::endl;
    }

    for (auto && c: children) {
        c.print(indent + 1);
    }
}

#define BITMASK_ENUM(val, type) static_cast<type>(val & static_cast<int>(type::Bitmask))

Packet Packet::decode(ByteVectorIt bytes, ByteVectorIt& end) {
    // Get the metadata byte and advance the iterator
    uint8_t meta = *bytes++;
    uint8_t tag = meta & static_cast<int>(Tag::Bitmask);
    Class berClass = BITMASK_ENUM(meta, Class);
    Type type = BITMASK_ENUM(meta, Type);
    Packet* ret = nullptr;

    // Get the data size
    uint64_t dataLen = decodeInteger(bytes, bytes + 1);
    // Advance the iterator by one past the size byte (bytes == bytes[2:]
    bytes++;
    // If the data size is bigger than 127, adjust based on the data size size
    if ((dataLen & 128) != 0) {
        dataLen -= 128;
        auto realDataLen = decodeInteger(bytes, bytes + dataLen);
        bytes += dataLen;
        dataLen = realDataLen;
    }

    if (bytes + dataLen > end) {
        LOG_S(ERROR) << "End of BER packet is longer than the available bytes";
        throw Ldap::Exception(Ldap::ErrorCode::protocolError);
    }
    end = bytes + dataLen;
    if (type == Type::Constructed) {
        ret = new Packet(type, berClass, tag);
        while(bytes < end) {
            ByteVectorIt childEnd = end;
            auto child = Packet::decode(bytes, childEnd);
            ret->appendChild(child);
            bytes = childEnd;
        }
    } else {
        ret = new Packet(type, berClass, tag, bytes, bytes + dataLen);
    }

    // Use a unique_ptr to cleanup ret ptr when it goes out of scope
    std::unique_ptr<Packet> cleanup(ret);
    return *ret;
}

Packet Packet::decode(uint8_t meta, ByteVector& reqBuffer) {
    uint8_t tag = meta & static_cast<int>(Tag::Bitmask);
    Class berClass = BITMASK_ENUM(meta, Class);
    Type type = BITMASK_ENUM(meta, Type);

    Packet* ret = nullptr;
    if (type == Type::Constructed) {
        ret = new Packet(type, berClass, tag);
        auto bytes = reqBuffer.begin();
        auto end = reqBuffer.end();
        while(bytes < end) {
            ByteVectorIt childEnd = end;
            auto child = Packet::decode(bytes, childEnd);
            ret->appendChild(child);
            bytes = childEnd;
        }
    } else {
        ret = new Packet(type, berClass, tag, reqBuffer.begin(), reqBuffer.end());
    }

    // Use a unique_ptr to cleanup ret ptr when it goes out of scope
    std::unique_ptr<Packet> cleanup(ret);
    return *ret;
}

} // namespace Ber
