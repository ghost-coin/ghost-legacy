// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INSIGHT_TIMESTAMPINDEX_H
#define BITCOIN_INSIGHT_TIMESTAMPINDEX_H

#include <uint256.h>

struct CTimestampIndexIteratorKey {
    unsigned int timestamp;

    size_t GetSerializeSize() const {
        return 4;
    }
    template<typename Stream>
    void Serialize(Stream& s) const {
        ser_writedata32be(s, timestamp);
    }
    template<typename Stream>
    void Unserialize(Stream& s) {
        timestamp = ser_readdata32be(s);
    }

    explicit CTimestampIndexIteratorKey(unsigned int time) {
        timestamp = time;
    }

    CTimestampIndexIteratorKey() {
        SetNull();
    }

    void SetNull() {
        timestamp = 0;
    }
};

struct CTimestampIndexKey {
    unsigned int timestamp;
    uint256 blockHash;

    size_t GetSerializeSize() const {
        return 36;
    }
    template<typename Stream>
    void Serialize(Stream& s) const {
        ser_writedata32be(s, timestamp);
        blockHash.Serialize(s);
    }
    template<typename Stream>
    void Unserialize(Stream& s) {
        timestamp = ser_readdata32be(s);
        blockHash.Unserialize(s);
    }

    explicit CTimestampIndexKey(unsigned int time, uint256 hash) {
        timestamp = time;
        blockHash = hash;
    }

    CTimestampIndexKey() {
        SetNull();
    }

    void SetNull() {
        timestamp = 0;
        blockHash.SetNull();
    }
};

struct CTimestampBlockIndexKey {
    uint256 blockHash;

    size_t GetSerializeSize() const {
        return 32;
    }

    template<typename Stream>
    void Serialize(Stream& s) const {
        blockHash.Serialize(s);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        blockHash.Unserialize(s);
    }

    explicit CTimestampBlockIndexKey(uint256 hash) {
        blockHash = hash;
    }

    CTimestampBlockIndexKey() {
        SetNull();
    }

    void SetNull() {
        blockHash.SetNull();
    }
};

struct CTimestampBlockIndexValue {
    unsigned int ltimestamp;
    size_t GetSerializeSize() const {
        return 4;
    }

    template<typename Stream>
    void Serialize(Stream& s) const {
        ser_writedata32be(s, ltimestamp);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        ltimestamp = ser_readdata32be(s);
    }

    explicit CTimestampBlockIndexValue (unsigned int time) {
        ltimestamp = time;
    }

    CTimestampBlockIndexValue() {
        SetNull();
    }

    void SetNull() {
        ltimestamp = 0;
    }
};

#endif // BITCOIN_INSIGHT_TIMESTAMPINDEX_H
