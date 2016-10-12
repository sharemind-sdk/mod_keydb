/*
 * Copyright (C) 2016 Cybernetica
 *
 * Research/Commercial License Usage
 * Licensees holding a valid Research License or Commercial License
 * for the Software may use this file according to the written
 * agreement between you and Cybernetica.
 *
 * GNU General Public License Usage
 * Alternatively, this file may be used under the terms of the GNU
 * General Public License version 3.0 as published by the Free Software
 * Foundation and appearing in the file LICENSE.GPL included in the
 * packaging of this file.  Please review the following information to
 * ensure the GNU General Public License version 3.0 requirements will be
 * met: http://www.gnu.org/copyleft/gpl-3.0.html.
 *
 * For further information, please contact us at sharemind@cyber.ee.
 */

#include <algorithm>
#include <LogHard/Logger.h>
#include <sharemind/EndianMacros.h>
#include <sharemind/libconsensusservice.h>
#include <sharemind/libmodapi/api_0x1.h>
#include <sharemind/libprocessfacility.h>
#include <sharemind/PotentiallyVoidTypeInfo.h>
#include "Intersection.h"
#include "ModuleData.h"

namespace {

using GlobalIdSizeType = SharemindGlobalIdSizeType;
using ElementLengthType = uint32_t; // comes from redis max key length
using sharemind::ptrAdd;
constexpr size_t ElementLengthSize = sizeof(ElementLengthType);

struct ConsensusData {
    ConsensusData(const std::vector<std::string> & keys_,
                    std::vector<std::string> & toDelete_)
        : keys(keys_)
        , toDelete(toDelete_)
    { }
    const std::vector<std::string> & keys;
    std::vector<std::string> & toDelete;
    bool localResult;
    bool globalResult;
};

GlobalIdSizeType readSize(void const * data) noexcept {
    GlobalIdSizeType size;
    std::memcpy(&size, data, sizeof(size));
    return sharemind::netToHostOrder(size);
};


template<class Container>
void deserialize(const SharemindConsensusDatum * proposal, Container & cont) {
    auto * readPtr = proposal->data;
    GlobalIdSizeType size = readSize(readPtr);
    readPtr = ptrAdd(readPtr, sizeof(GlobalIdSizeType) + size);
    ElementLengthType sizeOfCollection;
    memcpy(&sizeOfCollection, readPtr, ElementLengthSize);
    readPtr = ptrAdd(readPtr, ElementLengthSize);

    for (ElementLengthType i = 0; i < sizeOfCollection; ++i) {
        ElementLengthType elementLength;
        memcpy(&elementLength, readPtr, ElementLengthSize);
        readPtr = ptrAdd(readPtr, ElementLengthSize);
        cont.emplace_back(std::string(static_cast<const char *>(readPtr), elementLength));
        readPtr = ptrAdd(readPtr, elementLength);
    }
    assert(readPtr == ptrAdd(proposal->data, proposal->size));
}

template<class Container>
std::unique_ptr<uint8_t[]> serialize(const Container & cont,
                                     size_t & proposalSize,
                                     const void * const globalId,
                                     GlobalIdSizeType idSize)
{
    proposalSize = sizeof(GlobalIdSizeType) + idSize + ElementLengthSize;
    for (auto & key : cont) {
        proposalSize += key.size();
    }
    proposalSize += ElementLengthSize * cont.size();
    auto uPtr = std::unique_ptr<uint8_t[]>(new uint8_t[proposalSize]);
    auto * writePtr = uPtr.get();
    memcpy(writePtr, &idSize, sizeof(GlobalIdSizeType));
    writePtr = ptrAdd(writePtr, sizeof(GlobalIdSizeType));
    memcpy(writePtr, globalId, idSize);
    writePtr = ptrAdd(writePtr, idSize);

    ElementLengthType sizeOfCollection = cont.size();
    memcpy(writePtr, &sizeOfCollection, ElementLengthSize);
    writePtr = ptrAdd(writePtr, ElementLengthSize);

    ElementLengthType len;
    for (auto & key : cont) {
        len = key.size();
        memcpy(writePtr, &len, ElementLengthSize);
        writePtr = ptrAdd(writePtr, ElementLengthSize);
        memcpy(writePtr, key.data(), key.size());
        writePtr = ptrAdd(writePtr, key.size());
    }
    assert(writePtr == ptrAdd(uPtr.get(), proposalSize));
    return uPtr;
}

bool equivalent(const SharemindConsensusDatum * proposals, size_t count) {
    assert(proposals);
    assert(count > 0u);

    assert(proposals[0].size >= sizeof(GlobalIdSizeType)); ///< \bug throw?
    GlobalIdSizeType const firstSize = readSize(proposals[0].data);
    assert(proposals[0].size >= sizeof(GlobalIdSizeType) + firstSize); ///< \bug throw?
    auto const * const firstIdPtr =
            sharemind::ptrAdd(proposals[0].data, sizeof(GlobalIdSizeType));
    for (size_t i = 1u; i < count; i++) {
        assert(proposals[i].size >= sizeof(GlobalIdSizeType)); ///< \bug throw?
        if (readSize(proposals[i].data) != firstSize)
            return false;
        assert(proposals[i].size >= sizeof(GlobalIdSizeType) + firstSize); ///< \bug throw?
        auto const * const idPtr =
                sharemind::ptrAdd(proposals[i].data, sizeof(GlobalIdSizeType));
        if (memcmp(firstIdPtr, idPtr, firstSize) != 0)
            return false;
    }
    return true;
}

SharemindConsensusResultType execute(const SharemindConsensusDatum * proposals,
                                     size_t count,
                                     void * callbackPtr)
{
    assert(proposals);
    assert(count > 0u);
    assert(callbackPtr);

    auto & conData =
            *static_cast<ConsensusData *>(callbackPtr);

    std::vector<std::vector<std::string>> sets(count);

    for (size_t i = 0; i < count; ++i) {
        deserialize(proposals + i, sets[i]);
    }

    // local elements
    for (auto & key : conData.keys) {
        bool existsInAll = true;
        for (size_t j = 0; j < count; ++j) {
            // we assume that the keys in the proposal are sorted!
            if (!std::binary_search(sets[j].begin(), sets[j].end(), key)) {
                existsInAll = false;
            }
        }
        if (!existsInAll) {
            conData.toDelete.emplace_back(key);
        }
    }

    return conData.localResult = true;
}

void commit(const SharemindConsensusDatum * proposals,
            size_t count,
            const SharemindConsensusResultType * results,
            void * callbackPtr)
{
    assert(proposals);
    (void) proposals;
    assert(count > 0u);
    assert(results);
    assert(callbackPtr);

    // Get the global result from all of the local results
    bool success = true;
    for (size_t i = 0u; i < count; ++i) {
        if (!static_cast<bool>(results[i])) {
            success = false;
            break;
        }
    }

    auto & consensusData =
            *static_cast<ConsensusData *>(callbackPtr);
    consensusData.globalResult = success;
}

} /* namespace { */

SharemindOperationType const intersectionOperation = {
    &equivalent,
    &execute,
    &commit,
    "keydb_intersection"
};


bool intersection(const std::vector<std::string> & keys,
                  std::vector<std::string> & toDelete,
                  const SharemindModuleApi0x1SyscallContext * c)
{
    assert(std::is_sorted(keys.begin(), keys.end()) && "intersection called with unsorted keys");
    auto & mod = *static_cast<const ModuleData *>(c->moduleHandle);
    if (!mod.consensusFacility) {
        mod.logger.warning() << "Doing intersection without consensus service is a NOP!";
        return true;
    }

    using CPF = SharemindProcessFacility;
    auto * processFacility = static_cast<const CPF *>(c->process_internal);

    auto globalIdSize = processFacility->globalIdSize(processFacility);
    mod.logger.debug() << "keydb_intersection ";
    const void * globalId = processFacility->globalId(processFacility);

    if (!globalId) {
        mod.logger.debug() << "keydb_intersectio: no global id";
        globalIdSize = 0;
    }

    size_t proposalSize;
    auto proposal = serialize(keys, proposalSize, globalId, globalIdSize);
    ConsensusData conData(keys, toDelete);
    SharemindConsensusFacilityError err;
    err = mod.consensusFacility->blocking_propose(mod.consensusFacility,
                                                 "keydb_intersection",
                                                 proposalSize,
                                                 proposal.get(),
                                                 &conData);
    return err == SHAREMIND_CONSENSUS_FACILITY_OK;
}
