#include <stdint.h>
#include <memory>
#include <vector>

namespace Ber {

enum class Tag {
	EOC              = 0x00,
	Boolean          = 0x01,
	Integer          = 0x02,
	BitString        = 0x03,
	OctetString      = 0x04,
	NullValue        = 0x05,
	ObjectIdentifier = 0x06,
	ObjectDescriptor = 0x07,
	External         = 0x08,
	RealFloat        = 0x09,
	Enumerated       = 0x0a,
	EmbeddedPDV      = 0x0b,
	UTF8String       = 0x0c,
	RelativeOID      = 0x0d,
	Sequence         = 0x10,
	Set              = 0x11,
	NumericString    = 0x12,
	PrintableString  = 0x13,
	T61String        = 0x14,
	VideotexString   = 0x15,
	IA5String        = 0x16,
	UTCTime          = 0x17,
	GeneralizedTime  = 0x18,
	GraphicString    = 0x19,
	VisibleString    = 0x1a,
	GeneralString    = 0x1b,
	UniversalString  = 0x1c,
	CharacterString  = 0x1d,
	BMPString        = 0x1e,
	Bitmask          = 0x1f, // xxx11111b
};

enum class Class {
    Universal   = 0,   // 00xxxxxxb
	Application = 64,  // 01xxxxxxb
	Context     = 128, // 10xxxxxxb
	Private     = 192, // 11xxxxxxb
	Bitmask     = 192, // 11xxxxxxb
};

enum class Type {
	Primative   = 0,
    Constructed = 32,
	Bitmask     = 32, // xx1xxxxxb
};

using ByteVector = std::vector<uint8_t>;
using ByteVectorIt = ByteVector::iterator;
using ByteVectorCit = ByteVector::const_iterator;

void encodeInteger(int64_t val, ByteVector& out);
uint64_t decodeInteger(ByteVectorCit begin, ByteVectorCit end);

struct Packet {
    Packet(Type _type, Class _class, uint8_t _tag, std::string _value);
    Packet(Type _type, Class _class, uint8_t _tag, uint64_t  _value);
    Packet(Type _type, Class _class, uint8_t _tag, bool _value);
    Packet(Type _type, Class _class, uint8_t _tag, ByteVectorIt start, ByteVectorIt end);
    Packet(Type _type, Class _class, uint8_t _tag);

    Packet(Type _type, Class _class, Tag _tag):
        Packet(_type, _class, static_cast<uint8_t>(_tag)) {};
    Packet(Tag _tag, std::string _value):
        Packet(Type::Primative, Class::Universal, static_cast<uint8_t>(_tag), _value) {};
    Packet(Tag _tag, uint64_t  _value):
        Packet(Type::Primative, Class::Universal, static_cast<uint8_t>(_tag), _value) {};
    Packet(Tag _tag, bool _value):
        Packet(Type::Primative, Class::Universal, static_cast<uint8_t>(_tag), _value) {};
    Packet(Tag _tag, ByteVectorIt start, ByteVectorIt end):
        Packet(Type::Primative, Class::Universal, static_cast<uint8_t>(_tag), start, end) {};
    Packet(Tag _tag):
        Packet(Type::Primative, Class::Universal, static_cast<uint8_t>(_tag)) {};

    static Packet decode(ByteVectorIt bytes, ByteVectorIt& end);
    static Packet decode(uint8_t meta, ByteVector& reqBuffer);

    ~Packet() {};

    void appendChild(Packet p);
    size_t length();
    void copyBytes(ByteVector& out, bool topLevel = true);
    void print(int indent = 0);

    operator uint64_t() const { return Ber::decodeInteger(data.begin(), data.end()); }
    operator std::string() const { return std::string(data.begin(), data.end()); }
    operator bool() const {
        if (data.size() == 0)
            return false;
        return (data[0] != 0);
    }

    Type type;
    Class berClass;
    uint8_t tag;
    ByteVector data;
    std::vector<Packet> children;
};


} // namespace Ber
