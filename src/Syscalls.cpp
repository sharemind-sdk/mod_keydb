/*
 * Copyright (C) Cybernetica
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
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <exception>
#include <future>
#include <hiredis/hiredis.h>
#include <iostream>
#include <LogHard/Logger.h>
#include <memory>
#include <set>
#include <sharemind/AccessControlProcessFacility.h>
#include <sharemind/AssertReturn.h>
#include <sharemind/datastoreapi.h>
#include <sharemind/DebugOnly.h>
#include <sharemind/ExceptionMacros.h>
#include <sharemind/Concat.h>
#include <sharemind/libprocessfacility.h>
#include <sharemind/MakeUnique.h>
#include <sharemind/module-apis/api_0x1.h>
#include <sharemind/Range.h>
#include <sharemind/SyscallsCommon.h>
#include <sharemind/StringHashTablePredicate.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>
#include "Intersection.h"
#include "ModuleData.h"


#define SHAREMIND_DEFINE_SYSCALL(name,nargs,rv,nrefs,ncrefs,...) \
    SHAREMIND_EXTERN_C_BEGIN \
    SHAREMIND_MODULE_API_0x1_SYSCALL(name, args, num_args, refs, crefs, \
                                     returnValue, c) \
    { \
        if (!SyscallArgs<nargs,rv,nrefs,ncrefs>::check(num_args, \
                                                       refs, \
                                                       crefs, \
                                                       returnValue)) \
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL; \
        assert(c->moduleHandle); \
        auto & mod = *static_cast<ModuleData * const>(c->moduleHandle); \
        try { \
            __VA_ARGS__ \
            return SHAREMIND_MODULE_API_0x1_OK; \
        } catch (std::exception & exception) { \
            mod.logger.error() << exception.what(); \
            mod.logger.error() << "in " #name; \
            return catchModuleApiErrors(); \
        } catch (...) { \
            mod.logger.error() << "Error in " #name ; \
            return catchModuleApiErrors(); \
        } \
    } \
    SHAREMIND_EXTERN_C_END

namespace {

template <typename T>
T * getFacility(SharemindModuleApi0x1SyscallContext & c,
                char const * const facilityName) noexcept
{
    auto * const f = c.processFacility(&c, facilityName);
    return f ? static_cast<T *>(f) : nullptr;
}

using namespace sharemind;

#define DEFINE_STATIC_PREDICATE(name, string) \
    auto const name ## Range(asLiteralStringRange(string)); \
    auto const name ## Predicate( \
            getOrCreateTemporaryStringHashTablePredicate(name ## Range));
DEFINE_STATIC_PREDICATE(rulesetName,  "sharemind:keydb")
DEFINE_STATIC_PREDICATE(readWildcard,  "*:read:*")
DEFINE_STATIC_PREDICATE(writeWildcard, "*:write:*")
DEFINE_STATIC_PREDICATE(scanWildcard,  "*:scan:*")
DEFINE_STATIC_PREDICATE(allWildcards,  "*:*:*")
#undef DEFINE_STATIC_PREDICATE

#define SHAREMIND_CHECK_PERMISSION(moduleContext, key, permission) \
    do { \
        auto const * const processFacility = \
                getFacility<SharemindProcessFacility>(*c, "ProcessFacility"); \
        if (!processFacility) \
            return SHAREMIND_MODULE_API_0x1_MISSING_FACILITY; \
        auto const programName(processFacility->programName(processFacility)); \
        auto const * const aclFacility = \
                getFacility<AccessControlProcessFacility>( \
                                *c, \
                                "AccessControlProcessFacility"); \
        if (!aclFacility) \
            return SHAREMIND_MODULE_API_0x1_MISSING_FACILITY; \
        if (aclFacility->check( \
                    rulesetNamePredicate, \
                    concat(key, ":" #permission ":", programName), \
                    concat(key, ":" #permission ":*"), \
                    concat(key, ":*:", programName), \
                    concat(key, ":*:*"), \
                    concat("*:" #permission ":", programName), \
                    permission ## WildcardPredicate, \
                    concat("*:*:", programName), \
                    allWildcardsPredicate \
                ) != AccessResult::Allowed) \
            return SHAREMIND_MODULE_API_0x1_ACCESS_DENIED; \
    } while(false)


// names used for specific datastore namespaces
constexpr std::array<const char *, 3> dataStores{{"keydb",
                                                  "keydb_get",
                                                  "keydb_scan"}};
enum DataStoreNamespace {
    NS_KEYDB = 0,
    NS_GET = 1,
    NS_SCAN = 2,
    NS_MAX = NS_SCAN
};
static_assert(dataStores.size() == NS_MAX + 1,
              "DataStoreNamespace enum and dataStores array must be in sync!");

inline SharemindDataStoreFactory & getDataStoreFactory(
        SharemindModuleApi0x1SyscallContext * c)
{
    if (auto * const factory =
                getFacility<SharemindDataStoreFactory>(*c, "DataStoreFactory"))
        return *factory;
    throw std::logic_error("DataStoreFactory is missing!");
}

inline SharemindDataStore * getDataStore(
        SharemindModuleApi0x1SyscallContext * c,
        DataStoreNamespace ns)
{
    auto & factory = getDataStoreFactory(c);
    return factory.get_datastore(&factory, dataStores[ns]);
}

template <typename T>
inline T & getItem(SharemindModuleApi0x1SyscallContext * c, const char * name) {
    auto * store = getDataStore(c, NS_KEYDB);
    T * item = static_cast<T *>(store->get(store, name));
    if (!item)
        throw std::logic_error("Cannot get some process instance specific "
                               "data. Make sure to call keydb_connect!");
    return *item;
}

class SynchronousRedisClient {

public: /* Types: */

    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wunused"
    #pragma GCC diagnostic ignored "-Wunused-function"
    #ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wunused-member-function"
    #endif
    SHAREMIND_DECLARE_EXCEPTION_NOINLINE(std::exception, Exception);
    SHAREMIND_DECLARE_EXCEPTION_CONST_STDSTRING_NOINLINE(Exception,
                                                         HiredisException);
    SHAREMIND_DECLARE_EXCEPTION_NOINLINE(Exception, ConversionException);
    SHAREMIND_DECLARE_EXCEPTION_CONST_MSG_NOINLINE(ConversionException,
                                                   ReplyNotStringException);
    SHAREMIND_DECLARE_EXCEPTION_CONST_MSG_NOINLINE(ConversionException,
                                                   ReplyNotArrayException);
    #ifdef __clang__
    #pragma clang diagnostic pop
    #endif
    #pragma GCC diagnostic pop

    class Reply {

        friend class SynchronousRedisClient;

    private: /* Types: */

        using ReplyPtr =
                std::unique_ptr<::redisReply, void (*)(::redisReply * const)>;

    public: /* Methods: */

        Reply(Reply &&) noexcept = default;
        Reply & operator =(Reply &&) noexcept = default;

        bool isError() const noexcept
        { return m_reply && (m_reply->type == REDIS_REPLY_ERROR); }

        std::string asString() const {
            assert(m_reply);
            if (m_reply->type != REDIS_REPLY_STRING)
                throw ReplyNotStringException();
            return getString();
        }

        std::vector<Reply> asArray() const {
            assert(m_reply);
            if (m_reply->type != REDIS_REPLY_ARRAY)
                throw ReplyNotArrayException();
            std::vector<Reply> r;
            auto const numElements(m_reply->elements);
            r.reserve(numElements);
            for (std::size_t  i = 0u; i < numElements; ++i)
                r.emplace_back(Reply(m_reply->element[i], nullptr));
            return r;
        }

        std::string errorString() const {
            assert(m_reply);
            if (m_reply->type != REDIS_REPLY_ERROR)
                throw ReplyNotStringException();
            return getString();
        }

    private: /* Methods: */

        std::string getString() const {
            assert(m_reply);
            using U =
                    std::make_unsigned<
                        std::decay<decltype(m_reply->len)>::type
                    >::type;
            return std::string(m_reply->str, static_cast<U>(m_reply->len));
        }

        static void doFree(::redisReply * const r) noexcept
        { ::freeReplyObject(r); }

        static void noFree(::redisReply * const) noexcept {}

        Reply(::redisReply * const reply)
            : m_reply(reply, &Reply::doFree)
        {}

        Reply(::redisReply * const reply, decltype(nullptr) const)
            : m_reply(reply, &Reply::noFree)
        {}

    private: /* Fields: */

        ReplyPtr m_reply;

    };

private: /* Types: */

    struct HiredisContextDeleter {
        void operator()(::redisContext * const p) const noexcept
        { ::redisFree(p); }
    };

    using ContextPtr = std::unique_ptr<::redisContext, HiredisContextDeleter>;

public: /* Methods: */

    void connect(std::string const & hostname, std::uint16_t port) {
        assert(!m_redisContext);
        ContextPtr context(::redisConnect(hostname.c_str(), port));
        if (!context)
            throw std::bad_alloc();
        if (context->err)
            throw HiredisException(std::string("Hiredis error: ")
                                   + context->errstr);
        m_redisContext = std::move(context);
    }

    void disconnect() noexcept { m_redisContext.reset(); }

    template <typename ... Args>
    Reply command(Args && ... args) {
        if (auto * reply = ::redisCommand(m_redisContext.get(),
                                          std::forward<Args>(args)...))
            return static_cast<::redisReply *>(reply);
        throw HiredisException(std::string("Hiredis error: ")
                               + m_redisContext->errstr);
    }

private: /* Fields: */

    ContextPtr m_redisContext;

}; // class SynchronousRedisClient

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused"
#pragma GCC diagnostic ignored "-Wunused-function"
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-member-function"
#endif
SHAREMIND_DEFINE_EXCEPTION_NOINLINE(std::exception,
                                    SynchronousRedisClient::,
                                    Exception);
SHAREMIND_DEFINE_EXCEPTION_CONST_STDSTRING_NOINLINE(Exception,
                                                    SynchronousRedisClient::,
                                                    HiredisException);
SHAREMIND_DEFINE_EXCEPTION_NOINLINE(Exception,
                                    SynchronousRedisClient::,
                                    ConversionException);
SHAREMIND_DEFINE_EXCEPTION_CONST_MSG_NOINLINE(ConversionException,
                                              SynchronousRedisClient::,
                                              ReplyNotStringException,
                                              "Redis reply was not a string!");
SHAREMIND_DEFINE_EXCEPTION_CONST_MSG_NOINLINE(ConversionException,
                                              SynchronousRedisClient::,
                                              ReplyNotArrayException,
                                              "Redis reply was not an array!");
#ifdef __clang__
#pragma clang diagnostic pop
#endif
#pragma GCC diagnostic pop

inline SynchronousRedisClient & getClient(
        SharemindModuleApi0x1SyscallContext * c)
{ return getItem<SynchronousRedisClient>(c, "Client"); }

inline ModuleData::HostConfiguration & getHostConf(
        SharemindModuleApi0x1SyscallContext * c)
{ return getItem<ModuleData::HostConfiguration>(c, "HostConfiguration"); }

bool scanAndClean(SharemindModuleApi0x1SyscallContext * c,
                  char const * const pattern,
                  std::vector<std::string> & orderedKeys,
                  bool cleanUpOrderedKeys = false)
{
    auto & client = getClient(c);

    {
        auto & hostconf = getHostConf(c);
        std::set<std::string> keys;
        std::uint64_t cursor = 0;
        std::string str_cursor = "0";

        // make the first request
        auto reply(client.command("SCAN %s MATCH %s COUNT %s",
                                  str_cursor.c_str(),
                                  pattern,
                                  hostconf.scanCount.c_str()));
        do {
            // get the response
            auto const parts(reply.asArray());
            str_cursor = parts[0].asString();

            std::istringstream iss(str_cursor);
            iss >> cursor;

            if (cursor) {
                // make the next request
                reply = client.command("SCAN %s MATCH %s COUNT %s",
                                       str_cursor.c_str(),
                                       pattern,
                                       hostconf.scanCount.c_str());
            }
            /* While the next response arrives store the prevoius response into
               set: */
            auto const replies(parts[1].asArray());
            for (auto & r : replies)
                keys.emplace(r.asString());
        } while (cursor);

        // Move all elements from keys to orderedKeys:
        for (auto & key : keys)
            orderedKeys.emplace_back(std::move(key));
    }

    std::vector<std::string> toDelete;
    if (intersection(orderedKeys, toDelete, c)) {
        if (!toDelete.empty()) {
            std::ostringstream oss;
            oss << "DEL";
            for (auto const & key : toDelete)
                oss << ' ' << key;
            client.command(oss.str().c_str());
        }
        if (cleanUpOrderedKeys) {
            for (auto & k : toDelete) {
                auto it = std::lower_bound(orderedKeys.begin(),
                                           orderedKeys.end(),
                                           k);
                orderedKeys.erase(it);
            }
        }
        return true;
    }
    return false;
}

struct ScanCursor {
    std::vector<std::string> keys;
    decltype(keys.size()) cursor = 0u;
};

} /* namespace { */

SHAREMIND_DEFINE_SYSCALL(keydb_connect, 0, false, 0, 1,
        (void)args;

        if (crefs[0].size < 1u)
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
        auto const key = static_cast<char const *>(crefs[0u].pData);
        if (key[crefs[0].size - 1u] != '\0')
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;

        auto * store = getDataStore(c, NS_KEYDB);

        if (store->get(store, "Client")) {
            mod.logger.error() << "You have already called keydb_connect! "
                                  "First call keydb_disconnect to drop the old "
                                  "connection.";
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
        }

        auto const it(mod.hostMap.find(key));
        if (it == mod.hostMap.end()) {
            mod.logger.error() << "Could not find the host \"" << key
                << "\" in the module hosts configuration.";
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
        }
        auto & hostConfiguration = it->second;

        static auto const deleter =
                [](void * const p) noexcept
                { delete static_cast<SynchronousRedisClient *>(p); };

        auto * const client = new SynchronousRedisClient;
        store->set(store, "Client", client, +deleter);
        store->set(store, "HostConfiguration", &hostConfiguration, nullptr);

        client->connect(hostConfiguration.hostname, hostConfiguration.port);
    );

SHAREMIND_DEFINE_SYSCALL(keydb_disconnect, 0, false, 0, 0,
        (void)args;

        getClient(c).disconnect();

        auto & factory = getDataStoreFactory(c);
        for (auto ns : dataStores) {
            auto * store = factory.get_datastore(&factory, ns);
            store->clear(store);
        }
    );

SHAREMIND_DEFINE_SYSCALL(keydb_set, 1, false, 0, 2,
        if (args[0u].uint64[0u] > 1)
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
        if (crefs[0u].size < 1u)
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
        auto const key = static_cast<char const *>(crefs[0u].pData);
        if (key[crefs[0u].size - 1u] != '\0')
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
        auto const keySize = std::strlen(key);

        auto const value = static_cast<char const *>(crefs[1u].pData);
        bool const valueIsArray = args[0u].uint64[0u];

        // arrays need size -1, scalars do not need it:
        if (valueIsArray && (crefs[1u].size < 1u
                             || value[crefs[1u].size - 1u] != '\0'))
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
        auto const valueSize =
                valueIsArray ? crefs[1u].size - 1u : crefs[1u].size;

        SHAREMIND_CHECK_PERMISSION(c, key, write);

        mod.logger.debug() << "Set with key \"" << key << "\" size = "
                           << valueSize;

        auto const reply(getClient(c).command(
                             getHostConf(c).disableOverwrite
                             ? "SET %b %b NX"
                             : "SET %b %b",
                             key,
                             keySize,
                             value,
                             valueSize));
        if (reply.isError())
            mod.logger.error() << reply.errorString();
    );

SHAREMIND_DEFINE_SYSCALL(keydb_get_size, 1, true, 0, 1,
        (void) args;

        if (crefs[0u].size < 1u)
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
        auto const key = static_cast<char const *>(crefs[0].pData);
        if (key[crefs[0u].size - 1u] != '\0')
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
        SHAREMIND_CHECK_PERMISSION(c, key, read);

        mod.logger.debug() << "keydb_get_size with key \"" << key << '\"';

        // store returned data in heap
        auto heapString(makeUnique<std::string>(
                            getClient(c).command("GET %s", key).asString()));
        returnValue->uint64[0] = heapString->size();

        auto * store = getDataStore(c, NS_GET); // May throw

        std::uint64_t id = 0;
        char idString[21]; // 2^64 == 18 446 744 073 709 551 616
        do {
            std::sprintf(idString, "%" PRIu64, id);
            ++id;
        } while (!!store->get(store, idString));

        static auto const deleter =
                [](void * const p) noexcept
                { delete static_cast<std::string *>(p); };
        store->set(store, idString, heapString.release(), +deleter);

        /// \bug This does not pass/return a value to the caller:
        args[0].uint64[0] = id - 1;
    );

SHAREMIND_DEFINE_SYSCALL(keydb_get, 1, false, 1, 0,
        mod.logger.debug() << "keydb_get";

        auto * store = getDataStore(c, NS_GET);

        char id[21]; // 2^64 == 18 446 744 073 709 551 616
        std::sprintf(id, "%" PRIu64, args[0].uint64[0]);
        auto const * data = static_cast<std::string *>(store->get(store, id));
        if (!data)
            throw std::logic_error("Cannot get instance of data, was "
                                   "keydb_get_size called before?");

        mod.logger.debug() << "reference size, data size: "
            << refs[0].size << ", " << data->size();

        /// \todo Write different syscalls for array and scalar
        auto const refSize = refs[0u].size;
        auto const dataSize = data->size();
        if (refSize == dataSize) {
            std::memcpy(refs[0u].pData, data->data(), dataSize);
        } else if (refSize == dataSize + 1u) {
            std::memcpy(refs[0u].pData, data->data(), dataSize);
            (*(static_cast<char *>(refs[0u].pData) + dataSize)) = '\0';
        } else {
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
        }

        // free data from heap
        store->remove(store, id);
    );

SHAREMIND_DEFINE_SYSCALL(keydb_del, 0, false, 0, 1,
        (void) args;

        if (crefs[0u].size < 1u)
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
        auto const key = static_cast<char const *>(crefs[0].pData);
        if (key[crefs[0u].size - 1u] != '\0')
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
        SHAREMIND_CHECK_PERMISSION(c, key, write);
        getClient(c).command("DEL %s", key);
    );

/*
    System call arguments: <none>
    System call constant references:
        # The zero-terminated search pattern.
    System call references:
        # Reference to an uint64 where the size of the first key name is stored
          if matching keys were found.
    Returns an uint64 scan cursor, 0 if no matching keys were found.
*/
SHAREMIND_DEFINE_SYSCALL(keydb_scan, 0, true, 1, 1,
    (void) args;

    using ReturnSizeType = std::decay<decltype(returnValue->uint64[0u])>::type;
    if (refs[0u].size != sizeof(ReturnSizeType))
        return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
    if (crefs[0u].size < 1u)
        return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
    auto const pattern = static_cast<char const *>(crefs[0u].pData);
    if (pattern[crefs[0].size - 1u] != '\0')
        return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
    SHAREMIND_CHECK_PERMISSION(c, pattern, scan);

    auto & store = *assertReturn(getDataStore(c, NS_SCAN));

    // Calculate next free ID (0 is reserved for no results):
    char idString[21]; // 2^64 == 18 446 744 073 709 551 616
    std::uint64_t id = 1u;
    for (;;) { /// \todo Refactor from linear to at least logarithmic complexity
        std::sprintf(idString, "%" PRIu64, id);
        if (!store.get(&store, idString))
            break;
        if (!++id)
            return SHAREMIND_MODULE_API_0x1_OUT_OF_MEMORY;
    }

    // Allocate storage for scan result:
    auto newScan(makeUnique<ScanCursor>());
    static auto const deleter =
            [](void * const p) noexcept
            { delete static_cast<ScanCursor *>(p); };
    if (!store.set(&store, idString, newScan.get(), +deleter)) {
        newScan.release();
        /// \todo maybe should return something else? C interfaces... ;(
        return SHAREMIND_MODULE_API_0x1_OUT_OF_MEMORY;
    }
    ScanCursor * const scanCursor = newScan.release();

    /* Run consensus because scan on redis does not guarantee order of
       keys: */
    try {
        scanAndClean(c, pattern, scanCursor->keys, true);
    } catch (...) {
        SHAREMIND_DEBUG_ONLY(auto const r =) store.remove(&store, idString);
        assert(r);
        throw;
    }

    if (scanCursor->keys.empty()) {
        SHAREMIND_DEBUG_ONLY(auto const r =) store.remove(&store, idString);
        assert(r);
        returnValue->uint64[0u] = 0u;
    } else {
        // Return cursor ID:
        assert(id != 0u);
        returnValue->uint64[0u] = id;

        // Store first element size in refs[0u]:
        auto const elemSize = scanCursor->keys.front().size();
        static_assert(std::numeric_limits<decltype(elemSize)>::max()
                      <= std::numeric_limits<ReturnSizeType>::max(), "");
        ReturnSizeType const retElemSize = elemSize;
        std::memcpy(refs[0u].pData, &retElemSize, sizeof(retElemSize));
    }
);

/*
    System call arguments:
        # An uint64 scan cursor.
    System call constant references: <none>
    System call references:
        # Reference to an array of bytes where the key name should be copied to.
          At most max(size of reference, size of key name) bytes are copied to
          the beginning of this reference.
    Returns an uint64 size of the next key name.
    Notes: Also deallocates the scan cursor if the all the elements will be
           popped as a result of the call.
*/
SHAREMIND_DEFINE_SYSCALL(keydb_scan_cursor_pop, 1, true, 1, 0,
    auto const resultIndex = args[0u].uint64[0u];
    if (resultIndex == 0u)
        return SHAREMIND_MODULE_API_0x1_INVALID_CALL;

    char id[21]; // 2^64 == 18 446 744 073 709 551 616
    std::sprintf(id, "%" PRIu64, resultIndex);
    auto & store = *assertReturn(getDataStore(c, NS_SCAN));
    if (auto * value = store.get(&store, id)) {
        auto & scanCursor = *static_cast<ScanCursor *>(value);
        assert(scanCursor.cursor < scanCursor.keys.size());
        auto & elem = scanCursor.keys[scanCursor.cursor];
        assert(!elem.empty());
        auto const elemSize = elem.size();
        auto const refSize = refs[0u].size;
        if (refSize < elemSize) {
            std::memcpy(refs[0u].pData, elem.data(), refSize);
        } else {
            std::memcpy(refs[0u].pData, elem.data(), elemSize);
        }

        /* If we have consumed all data, free the results. Otherwise
           just clear all key strings we've passed without removing
           them from the underlying vector container (which could be
           expensive). */
        ++scanCursor.cursor;
        if (scanCursor.cursor >= scanCursor.keys.size()) {
            store.remove(&store, id);
            returnValue->uint64[0u] = 0u;
        } else {
            elem.clear();

            // Return next element size:
            using R = std::decay<decltype(returnValue->uint64[0u])>::type;
            static_assert(std::numeric_limits<decltype(elemSize)>::max()
                          <= std::numeric_limits<R>::max(), "");
            assert(!scanCursor.keys[scanCursor.cursor].empty());
            returnValue->uint64[0u] = scanCursor.keys[scanCursor.cursor].size();
        }
    } else {
        return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
    }
);

/*
    System call arguments:
        # The scan cursor to deallocate.
    System call constant references: <none>
    System call references: <none>
    Doesn't returns any value.
*/
SHAREMIND_DEFINE_SYSCALL(keydb_scan_cursor_free, 1u, false, 0u, 0u,
    if (args[0u].uint64[0u] != 0u) {
        char id[21]; // 2^64 == 18 446 744 073 709 551 616
        std::sprintf(id, "%" PRIu64, args[0u].uint64[0u]);
        auto & store = *assertReturn(getDataStore(c, NS_SCAN));
        store.remove(&store, id);
    }
);

SHAREMIND_DEFINE_SYSCALL(keydb_clean, 0, true, 0, 1,
        (void) args;
        mod.logger.debug() << "keydb_clean";

        if (crefs[0].size < 1)
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
        auto const pattern = static_cast<char const *>(crefs[0].pData);
        if (pattern[crefs[0].size - 1u] != '\0')
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;

        std::vector<std::string> orderedKeys;
        returnValue->uint64[0] = scanAndClean(c, pattern, orderedKeys) ? 1 : 0;
    );
