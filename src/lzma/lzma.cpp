#include "lzma.h"

#include <algorithm>
#include <cstring>

namespace vmp {
namespace lzma {
namespace {

const int kProbBits = 11;
const int kMoveBits = 5;
const std::uint16_t kProbInit = static_cast<std::uint16_t>(1u << (kProbBits - 1));

const std::uint32_t kTopValue = 1u << 24;

const int kStates = 12;
const int kMaxPosBits = 4;
const int kMinMatchLen = 2;
const int kMaxMatchLen = kMinMatchLen + 16 + 256 - 1;

const int kMinLC = 0, kMaxLC = 8;
const int kMinLP = 0, kMaxLP = 4;
const int kMinPB = 0, kMaxPB = 4;
const int kMaxPropertyCode = (kMaxPB + 1) * (kMaxLP + 1) * (kMaxLC + 1) - 1;

const std::uint32_t kMinDictCap = 4096;
const std::uint32_t kMaxDictCap = 0xFFFFFFFFu;
const std::uint32_t kDefaultDictCap = (1u << 31) - 1;

const int kLenStates = 4;
const int kStartPosModel = 4;
const int kEndPosModel = 14;
const int kPosSlotBits = 6;
const int kAlignBits = 4;

const std::uint32_t kEosDist = 0xFFFFFFFFu;

const std::size_t kLiteralProbs = 0x300;

struct Prob {
    std::uint16_t value = kProbInit;

    void dec() {
        value = static_cast<std::uint16_t>(value - (value >> kMoveBits));
    }

    void inc() {
        value = static_cast<std::uint16_t>(value + (((1u << kProbBits) - value) >> kMoveBits));
    }

    std::uint32_t bound(std::uint32_t range) const {
        return (range >> kProbBits) * static_cast<std::uint32_t>(value);
    }
};

class RangeDecoder {
public:
    bool init(const std::uint8_t* data, std::size_t size) {
        data_ = data;
        size_ = size;
        pos_ = 0;
        nrange_ = 0xFFFFFFFFu;
        code_ = 0;

        std::uint8_t b = 0;
        if (!readByte(&b)) {
            fail("EOF");
            return false;
        }
        if (b != 0) {
            fail("newRangeDecoder: first byte not zero");
            return false;
        }
        for (int i = 0; i < 4; i++) {
            if (!updateCode()) {
                fail("EOF");
                return false;
            }
        }
        if (code_ >= nrange_) {
            fail("newRangeDecoder: d.code >= d.nrange");
            return false;
        }
        return true;
    }

    std::uint32_t decodeBit(Prob& p) {
        const std::uint32_t bound = p.bound(nrange_);
        std::uint32_t b;
        if (code_ < bound) {
            nrange_ = bound;
            p.inc();
            b = 0;
        } else {
            code_ -= bound;
            nrange_ -= bound;
            p.dec();
            b = 1;
        }
        normalize();
        return b;
    }

    std::uint32_t directDecodeBit() {
        nrange_ >>= 1;
        code_ -= nrange_;
        const std::uint32_t t = 0u - (code_ >> 31);
        code_ += nrange_ & t;
        const std::uint32_t b = (t + 1u) & 1u;
        normalize();
        return b;
    }

    bool possiblyAtEnd() const { return code_ == 0; }

    bool failed() const { return failed_; }
    bool eof() const { return eof_; }
    const std::string& error() const { return error_; }

private:
    void fail(const char* msg) {
        failed_ = true;
        error_ = msg;
    }

    bool readByte(std::uint8_t* out) {
        if (data_ == nullptr || pos_ >= size_) {
            eof_ = true;
            failed_ = true;
            return false;
        }
        *out = data_[pos_++];
        return true;
    }

    bool updateCode() {
        std::uint8_t b = 0;
        if (!readByte(&b)) {
            return false;
        }
        code_ = (code_ << 8) | static_cast<std::uint32_t>(b);
        return true;
    }

    void normalize() {
        if (nrange_ >= kTopValue) {
            return;
        }
        nrange_ <<= 8;
        updateCode();
    }

    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
    std::size_t pos_ = 0;
    std::uint32_t nrange_ = 0xFFFFFFFFu;
    std::uint32_t code_ = 0;
    bool failed_ = false;
    bool eof_ = false;
    std::string error_;
};

struct TreeCodec {
    int bits = 0;
    std::vector<Prob> probs;

    void init(int b) {
        bits = b;
        probs.assign(static_cast<std::size_t>(1) << b, Prob());
    }
};

std::uint32_t treeDecode(TreeCodec& tc, RangeDecoder& rd) {
    std::uint32_t m = 1;
    for (int j = 0; j < tc.bits; j++) {
        const std::uint32_t b = rd.decodeBit(tc.probs[m]);
        if (rd.failed()) {
            return 0;
        }
        m = (m << 1) | b;
    }
    return m - (1u << tc.bits);
}

std::uint32_t treeReverseDecode(TreeCodec& tc, RangeDecoder& rd) {
    std::uint32_t m = 1;
    std::uint32_t v = 0;
    for (int j = 0; j < tc.bits; j++) {
        const std::uint32_t b = rd.decodeBit(tc.probs[m]);
        if (rd.failed()) {
            return 0;
        }
        m = (m << 1) | b;
        v |= b << j;
    }
    return v;
}

struct LengthCodec {
    Prob choice[2];
    TreeCodec low[1 << kMaxPosBits];
    TreeCodec mid[1 << kMaxPosBits];
    TreeCodec high;

    void init() {
        choice[0] = Prob();
        choice[1] = Prob();
        for (int i = 0; i < (1 << kMaxPosBits); i++) {
            low[i].init(3);
            mid[i].init(3);
        }
        high.init(8);
    }

    std::uint32_t decode(RangeDecoder& rd, std::uint32_t posState) {
        std::uint32_t b = rd.decodeBit(choice[0]);
        if (rd.failed()) {
            return 0;
        }
        if (b == 0) {
            return treeDecode(low[posState & 0xF], rd);
        }
        b = rd.decodeBit(choice[1]);
        if (rd.failed()) {
            return 0;
        }
        if (b == 0) {
            return treeDecode(mid[posState & 0xF], rd) + 8u;
        }
        return treeDecode(high, rd) + 16u;
    }
};

struct DistCodec {
    TreeCodec posSlotCodecs[kLenStates];
    TreeCodec posModel[kEndPosModel - kStartPosModel];
    TreeCodec alignCodec;

    void init() {
        for (int i = 0; i < kLenStates; i++) {
            posSlotCodecs[i].init(kPosSlotBits);
        }
        for (int i = 0; i < kEndPosModel - kStartPosModel; i++) {
            const int posSlot = kStartPosModel + i;
            const int bits = (posSlot >> 1) - 1;
            posModel[i].init(bits);
        }
        alignCodec.init(kAlignBits);
    }

    std::uint32_t decode(RangeDecoder& rd, std::uint32_t l) {
        std::uint32_t lenState = l;
        if (lenState >= static_cast<std::uint32_t>(kLenStates)) {
            lenState = kLenStates - 1;
        }

        const std::uint32_t posSlot = treeDecode(posSlotCodecs[lenState], rd);
        if (rd.failed()) {
            return 0;
        }
        if (posSlot < static_cast<std::uint32_t>(kStartPosModel)) {
            return posSlot;
        }

        const std::uint32_t bits = (posSlot >> 1) - 1u;
        std::uint32_t dist = (2u | (posSlot & 1u)) << bits;

        if (posSlot < static_cast<std::uint32_t>(kEndPosModel)) {
            const std::uint32_t u = treeReverseDecode(posModel[posSlot - kStartPosModel], rd);
            if (rd.failed()) {
                return 0;
            }
            return dist + u;
        }

        const std::uint32_t numDirectBits = bits - kAlignBits;
        std::uint32_t u = 0;
        for (int i = static_cast<int>(numDirectBits) - 1; i >= 0; i--) {
            const std::uint32_t x = rd.directDecodeBit();
            if (rd.failed()) {
                return 0;
            }
            u = (u << 1) | x;
        }
        dist += u << kAlignBits;

        const std::uint32_t a = treeReverseDecode(alignCodec, rd);
        if (rd.failed()) {
            return 0;
        }
        return dist + a;
    }
};

struct State {
    std::uint32_t rep[4] = {0, 0, 0, 0};
    Prob isMatch[kStates << kMaxPosBits];
    Prob isRepG0Long[kStates << kMaxPosBits];
    Prob isRep[kStates];
    Prob isRepG0[kStates];
    Prob isRepG1[kStates];
    Prob isRepG2[kStates];
    std::vector<Prob> litProbs;
    LengthCodec lenCodec;
    LengthCodec repLenCodec;
    DistCodec distCodec;
    std::uint32_t state = 0;
    std::uint32_t posBitMask = 0;
    int lc = 0;
    int lp = 0;
    int pb = 0;

    void reset(int lc_, int lp_, int pb_) {
        lc = lc_;
        lp = lp_;
        pb = pb_;

        rep[0] = rep[1] = rep[2] = rep[3] = 0;
        state = 0;
        posBitMask = (1u << pb_) - 1u;

        for (int i = 0; i < kStates << kMaxPosBits; i++) {
            isMatch[i] = Prob();
            isRepG0Long[i] = Prob();
        }
        for (int i = 0; i < kStates; i++) {
            isRep[i] = Prob();
            isRepG0[i] = Prob();
            isRepG1[i] = Prob();
            isRepG2[i] = Prob();
        }

        litProbs.assign(kLiteralProbs << (lc_ + lp_), Prob());

        lenCodec.init();
        repLenCodec.init();
        distCodec.init();
    }

    void updateStateLiteral() {
        if (state < 4) {
            state = 0;
        } else if (state < 10) {
            state -= 3;
        } else {
            state -= 6;
        }
    }

    void updateStateMatch() {
        state = (state < 7) ? 7u : 10u;
    }

    void updateStateRep() {
        state = (state < 7) ? 8u : 11u;
    }

    void updateStateShortRep() {
        state = (state < 7) ? 9u : 11u;
    }

    std::uint8_t decodeLiteral(RangeDecoder& rd, std::uint32_t lzmaState,
                               std::uint8_t matchByte, std::uint32_t litState) {
        const std::size_t base = static_cast<std::size_t>(litState) * kLiteralProbs;
        std::uint32_t symbol = 1;

        if (lzmaState >= 7) {
            std::uint32_t m = matchByte;
            for (;;) {
                const std::uint32_t matchBit = (m >> 7) & 1u;
                m <<= 1;
                const std::size_t idx = ((1u + matchBit) << 8) | symbol;
                const std::uint32_t bit = rd.decodeBit(litProbs[base + idx]);
                if (rd.failed()) {
                    return 0;
                }
                symbol = (symbol << 1) | bit;
                if (matchBit != bit) {
                    break;
                }
                if (symbol >= 0x100) {
                    break;
                }
            }
        }

        while (symbol < 0x100) {
            const std::uint32_t bit = rd.decodeBit(litProbs[base + symbol]);
            if (rd.failed()) {
                return 0;
            }
            symbol = (symbol << 1) | bit;
        }
        return static_cast<std::uint8_t>(symbol - 0x100);
    }
};

class Decoder {
public:
    Decoder(State& st, std::size_t dictCap) : st_(st), dictCap_(dictCap) {}

    bool run(RangeDecoder& rd, std::vector<std::uint8_t>* out, std::string* err,
             std::size_t maxOutput = 0) {
        out_ = out;
        start_ = out->size();
        maxOutput_ = maxOutput;
        limitReached_ = false;

        for (;;) {
            if (maxOutput_ != 0 && head() >= maxOutput_) {
                return true;
            }
            const std::uint32_t state1 = st_.state;
            const std::uint32_t posState = static_cast<std::uint32_t>(head()) & st_.posBitMask;
            const std::uint32_t state2 = (state1 << kMaxPosBits) | posState;

            std::uint32_t bit = rd.decodeBit(st_.isMatch[state2]);
            if (rd.failed()) {
                return fail(rd, err);
            }

            if (bit == 0) {
                const std::uint8_t prev = byteAt(1);
                const std::uint32_t litState =
                    ((static_cast<std::uint32_t>(head()) & ((1u << st_.lp) - 1u)) << st_.lc) |
                    (static_cast<std::uint32_t>(prev) >> (8 - st_.lc));
                const std::uint8_t matchByte =
                    byteAt(static_cast<std::size_t>(st_.rep[0]) + 1u);
                const std::uint8_t b = st_.decodeLiteral(rd, st_.state, matchByte, litState);
                if (rd.failed()) {
                    return fail(rd, err);
                }
                writeByte(b);
                if (limitReached_) {
                    return true;
                }
                st_.updateStateLiteral();
                continue;
            }

            bit = rd.decodeBit(st_.isRep[state1]);
            if (rd.failed()) {
                return fail(rd, err);
            }

            if (bit == 0) {
                st_.rep[3] = st_.rep[2];
                st_.rep[2] = st_.rep[1];
                st_.rep[1] = st_.rep[0];
                st_.updateStateMatch();

                const std::uint32_t n = st_.lenCodec.decode(rd, posState);
                if (rd.failed()) {
                    return fail(rd, err);
                }
                const std::uint32_t dist = st_.distCodec.decode(rd, n);
                if (rd.failed()) {
                    return fail(rd, err);
                }
                st_.rep[0] = dist;

                if (dist == kEosDist) {
                    if (!rd.possiblyAtEnd()) {
                        if (err) *err = "lzma: data after end of stream marker";
                        return false;
                    }
                    return true;
                }

                if (!writeMatch(static_cast<std::size_t>(dist) + 1u,
                                static_cast<std::size_t>(n) + kMinMatchLen, err)) {
                    return false;
                }
                if (limitReached_) {
                    return true;
                }
                continue;
            }

            std::uint32_t dist = st_.rep[0];

            bit = rd.decodeBit(st_.isRepG0[state1]);
            if (rd.failed()) {
                return fail(rd, err);
            }

            if (bit == 0) {
                bit = rd.decodeBit(st_.isRepG0Long[state2]);
                if (rd.failed()) {
                    return fail(rd, err);
                }
                if (bit == 0) {
                    st_.updateStateShortRep();
                    if (!writeMatch(static_cast<std::size_t>(dist) + 1u, 1u, err)) {
                        return false;
                    }
                    if (limitReached_) {
                        return true;
                    }
                    continue;
                }
            } else {
                bit = rd.decodeBit(st_.isRepG1[state1]);
                if (rd.failed()) {
                    return fail(rd, err);
                }
                if (bit == 0) {
                    dist = st_.rep[1];
                } else {
                    bit = rd.decodeBit(st_.isRepG2[state1]);
                    if (rd.failed()) {
                        return fail(rd, err);
                    }
                    if (bit == 0) {
                        dist = st_.rep[2];
                    } else {
                        dist = st_.rep[3];
                        st_.rep[3] = st_.rep[2];
                    }
                    st_.rep[2] = st_.rep[1];
                }
                st_.rep[1] = st_.rep[0];
                st_.rep[0] = dist;
            }

            const std::uint32_t n = st_.repLenCodec.decode(rd, posState);
            if (rd.failed()) {
                return fail(rd, err);
            }
            st_.updateStateRep();
            if (!writeMatch(static_cast<std::size_t>(dist) + 1u,
                            static_cast<std::size_t>(n) + kMinMatchLen, err)) {
                return false;
            }
            if (limitReached_) {
                return true;
            }
        }
    }

private:
    std::size_t head() const { return out_->size() - start_; }

    std::size_t dictLen() const {
        return head() < dictCap_ ? head() : dictCap_;
    }

    std::uint8_t byteAt(std::size_t dist) const {
        if (dist == 0 || dist > dictLen()) {
            return 0;
        }
        return (*out_)[out_->size() - dist];
    }

    bool writeByte(std::uint8_t b) {
        if (maxOutput_ != 0 && head() >= maxOutput_) {
            limitReached_ = true;
            return false;
        }
        out_->push_back(b);
        return true;
    }

    bool writeMatch(std::size_t dist, std::size_t length, std::string* err) {
        if (dist == 0 || dist > dictLen()) {
            if (err) *err = "writeMatch: distance out of range";
            return false;
        }
        if (length == 0 || length > static_cast<std::size_t>(kMaxMatchLen)) {
            if (err) *err = "writeMatch: length out of range";
            return false;
        }
        for (std::size_t i = 0; i < length; i++) {
            if (maxOutput_ != 0 && head() >= maxOutput_) {
                limitReached_ = true;
                return true;
            }
            const std::uint8_t b = (*out_)[out_->size() - dist];
            out_->push_back(b);
        }
        return true;
    }

    static bool fail(const RangeDecoder& rd, std::string* err) {
        if (err) {
            *err = rd.eof() ? "unexpected EOF" : rd.error();
        }
        return false;
    }

    State& st_;
    std::size_t dictCap_ = 0;
    std::vector<std::uint8_t>* out_ = nullptr;
    std::size_t start_ = 0;
    std::size_t maxOutput_ = 0;
    bool limitReached_ = false;
};

}

bool decode(const Options& options,
            const std::uint8_t* header, std::size_t headerLen,
            std::uint8_t propsByte, std::size_t dictSize,
            const std::uint8_t* in, std::size_t inLen,
            std::vector<std::uint8_t>* out,
            std::string* err) {
    if (out == nullptr) {
        if (err) *err = "no output buffer";
        return false;
    }
    if (err) {
        err->clear();
    }

    std::uint8_t props = propsByte;
    std::uint64_t headerDictSize = static_cast<std::uint64_t>(dictSize);
    if (header != nullptr && headerLen >= 1) {
        props = header[0];
    }
    if (header != nullptr && headerLen >= 5) {
        headerDictSize = static_cast<std::uint64_t>(header[1]) |
                         (static_cast<std::uint64_t>(header[2]) << 8) |
                         (static_cast<std::uint64_t>(header[3]) << 16) |
                         (static_cast<std::uint64_t>(header[4]) << 24);
    }

    if (props > static_cast<std::uint8_t>(kMaxPropertyCode)) {
        if (err) *err = "lzma: invalid properties code";
        return false;
    }
    const int lc = props % 9;
    const int rest = props / 9;
    const int lp = rest % 5;
    const int pb = rest / 5;

    std::uint64_t dictCap = static_cast<std::uint64_t>(options.dictionarySize);
    if (dictCap == 0) {
        const std::uint64_t configCap = kDefaultDictCap;
        if (headerDictSize > configCap) {
            if (err) {
                *err = "lzma: header dictionary size " + std::to_string(headerDictSize) +
                       " exceeds configured dictionary capacity " + std::to_string(configCap);
            }
            return false;
        }
        dictCap = headerDictSize;
    } else if (dictCap > kMaxDictCap) {
        if (err) *err = "lzma: dictCap out of range";
        return false;
    }
    if (dictCap < kMinDictCap) {
        dictCap = kMinDictCap;
    }

    State st;
    st.reset(lc, lp, pb);

    RangeDecoder rd;
    if (!rd.init(in, inLen)) {
        if (err) *err = rd.error();
        return false;
    }

    Decoder dec(st, static_cast<std::size_t>(dictCap));
    return dec.run(rd, out, err, options.maxOutput);
}

bool decode(const std::uint8_t* header, std::size_t headerLen,
            std::uint8_t propsByte, std::size_t dictSize,
            const std::uint8_t* in, std::size_t inLen,
            std::vector<std::uint8_t>* out,
            std::string* err) {
    return decode(Options(), header, headerLen, propsByte, dictSize, in, inLen, out, err);
}

}
}
