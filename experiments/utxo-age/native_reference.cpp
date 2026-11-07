// Offline synthetic reference using the pinned Namecoin implementation itself.
// This program never links a node, opens a datadir, or creates a transaction.
#include <coins.h>
#include <hash.h>
#include <node/utxo_snapshot.h>
#include <script/names.h>
#include <streams.h>
#include <iostream>
#include <string>
#include <vector>

static std::string Hex(Span<const std::byte> data) {
    const char* digits = "0123456789abcdef";
    std::string out;
    for (auto b : data) {
        unsigned n = std::to_integer<unsigned>(b);
        out += digits[n >> 4]; out += digits[n & 15];
    }
    return out;
}

static CScript FromHex(const std::string& text) {
    CScript out;
    for (size_t i = 0; i < text.size(); i += 2)
        out.push_back(std::stoul(text.substr(i, 2), nullptr, 16));
    return out;
}

int main() {
    const std::string keyx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const std::string keyy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    const std::string oddy = "b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777";
    std::vector<std::string> scripts{
        "76a914" + std::string(40, '1') + "88ac", // compression code 0
        "a914" + std::string(40, '2') + "87",    // compression code 1
        "2102" + keyx + "ac", "2103" + keyx + "ac", // codes 2, 3
        "4104" + keyx + keyy + "ac", "4104" + keyx + oddy + "ac", // codes 4, 5
        "", "00", "512101", // raw and malformed prefix
        "5114" + std::string(40, '3') + "6d51", // NAME_NEW
        "520161010001766d6d51", // FIRSTUPDATE
        "53016101766d7551", // UPDATE
        "534c01614c01766151", // accepted nonminimal pushes + NOP
        "5301610176", // missing drop => ordinary by native classifier
        "510075", // empty NAME_NEW argument, classifier only
        "53016101766d", // no destination, classifier still recognizes name
        "515175", // OP_1 is not a data push in CNameScript
        "534d0100614e01000000767551", // PUSHDATA2/4
    };
    const std::vector<uint64_t> amounts{0,1,10,1000000,100000000,5000000000ULL,
        2100000000000000ULL,123456789,1000000000ULL,10000000000ULL,100000000000ULL};
    std::cout << "{\"coins\":[";
    HashWriter stats;
    DataStream grouped;
    for (size_t i = 0; i < scripts.size(); ++i) {
        CTxOut out;
        out.nValue = amounts[i % amounts.size()];
        out.scriptPubKey = FromHex(scripts[i]);
        const uint32_t height = i % 6;
        const bool cb = i % 2;
        Coin coin(out, height, cb);
        // Same field operations as kernel/coinstats.cpp::TxOutSer.
        uint256 txhash; txhash.begin()[0] = i + 1;
        Txid txid = Txid::FromUint256(txhash);
        stats << COutPoint(txid, 0) << static_cast<uint32_t>((height << 1) | cb) << out;
        // rpc/blockchain.cpp::CreateUTXOSnapshot's grouped serialization.
        grouped << txid;
        WriteCompactSize(grouped, 1);
        WriteCompactSize(grouped, 0);
        grouped << coin;
        DataStream encoded; encoded << coin;
        DataStream decoding(encoded);
        Coin decoded; decoding >> decoded;
        DataStream reencoded; reencoded << decoded;
        if (!decoding.empty() || Hex(encoded) != Hex(reencoded)) return 3;
        CNameScript name(out.scriptPubKey);
        std::string kind = "ordinary";
        if (name.isNameOp()) {
            switch (name.getNameOp()) {
            case OP_NAME_NEW: kind = "name_new"; break;
            case OP_NAME_FIRSTUPDATE: kind = "name_firstupdate"; break;
            case OP_NAME_UPDATE: kind = "name_update"; break;
            default: return 4;
            }
        }
        if (i) std::cout << ',';
        std::cout << "{\"height\":" << height << ",\"coinbase\":" << (cb ? "true" : "false")
                  << ",\"value\":" << out.nValue << ",\"script_hex\":\"" << scripts[i]
                  << "\",\"coin_hex\":\"" << Hex(encoded) << "\",\"kind\":\"" << kind << "\"}";
    }
    uint256 base;
    for (size_t i = 0; i < 32; ++i) base.begin()[i] = i;
    node::SnapshotMetadata metadata{{0xf9,0xbe,0xb4,0xfe}, base, scripts.size()};
    DataStream header; header << metadata;
    DataStream snapshot; snapshot << metadata; snapshot.write(grouped);
    std::cout << "],\"stats_hash\":\"" << stats.GetHash().ToString()
              << "\",\"snapshot_hex\":\"" << Hex(snapshot)
              << "\",\"header_hex\":\"" << Hex(header) << "\",\"integers\":[";
    const std::vector<uint64_t> ints{0,1,127,128,252,253,255,256,16383,16384,16511,16512,
        65535,65536,0xffffffffULL,0x100000000ULL,0xffffffffffffffffULL};
    for (size_t i = 0; i < ints.size(); ++i) {
        DataStream var, compact;
        WriteVarInt<DataStream, VarIntMode::DEFAULT>(var, ints[i]);
        WriteCompactSize(compact, ints[i]);
        if (i) std::cout << ',';
        std::cout << "{\"value\":" << ints[i] << ",\"varint\":\"" << Hex(var)
                  << "\",\"compact\":\"" << Hex(compact) << "\"}";
    }
    std::cout << "]}\n";
}
