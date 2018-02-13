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
#include <sharemind/datastoreapi.h>
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
        if (!sharemind::SyscallArgs<nargs,rv,nrefs,ncrefs>::check(num_args, refs, crefs, returnValue)) \
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL; \
        assert(c->moduleHandle); \
        auto & mod = *static_cast<sharemind::ModuleData * const>(c->moduleHandle); \
        try { \
            __VA_ARGS__ \
            return SHAREMIND_MODULE_API_0x1_OK; \
        } catch (std::exception & exception) { \
            mod.logger.error() << exception.what(); \
            mod.logger.error() << "in " #name; \
            return sharemind::catchModuleApiErrors(); \
        } catch (...) { \
            mod.logger.error() << "Error in " #name ; \
            return sharemind::catchModuleApiErrors(); \
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
#undef DEFINE_STATIC_PREDICATE

#define SHAREMIND_CHECK_PERMISSION(moduleContext, key, permission) \
    do { \
        auto const * const processFacility = \
                getFacility<SharemindProcessFacility>(*c, "ProcessFacility"); \
        if (!processFacility) \
            return SHAREMIND_MODULE_API_0x1_MISSING_FACILITY; \
        std::string const programName( \
                processFacility->programName(processFacility)); \
        auto const * const aclFacility = \
                getFacility<AccessControlProcessFacility>( \
                                *c, \
                                "AccessControlProcessFacility"); \
        if (!aclFacility) \
            return SHAREMIND_MODULE_API_0x1_MISSING_FACILITY; \
        if (aclFacility->check( \
                    rulesetNamePredicate, \
                    key + ":" #permission ":" + programName, \
                    key + ":" #permission ":*", \
                    "*:" #permission ":" + programName, \
                    permission ## WildcardPredicate \
                ) != AccessResult::Allowed) \
            return SHAREMIND_MODULE_API_0x1_ACCESS_DENIED; \
    } while(false)


// names used for specific datastore namespaces
constexpr std::array<const char *, 3> dataStores{{"keydb", "keydb_get", "keydb_scan"}};
enum DataStoreNamespace {
    NS_KEYDB = 0,
    NS_GET = 1,
    NS_SCAN = 2,
    NS_MAX = NS_SCAN
};
static_assert(dataStores.size() == NS_MAX + 1, "DataStoreNamespace enum and dataStores array must be in sync!");

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
    if (!item) {
        throw std::logic_error(
                "Cannot get some process instance specific data. Make sure to call keydb_connect!");
    }
    return *item;
}

class SynchronousRedisClient {

public: /* Types: */

    class Exception: public std::exception {};
    class HiredisError final: public Exception {

    public: /* Methods: */

        HiredisError(::redisContext const & context)
            : m_errorString(std::string("Hiredis error: ") + context.errstr)
        {}

        char const * what() const noexcept final override
        { return m_errorString.c_str(); }

    private: /* Fields: */

        std::string const m_errorString;

    };

    class ConversionError final: public Exception {

    public: /* Methods: */

        ConversionError(char const * const staticStr)
            : m_errorString(staticStr)
        {}

        char const * what() const noexcept final override
        { return m_errorString; }

    private: /* Fields: */

        char const * const m_errorString;

    };

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
                throw ConversionError("Redis reply was not a string!");
            return getString();
        }

        std::vector<Reply> asArray() const {
            assert(m_reply);
            if (m_reply->type != REDIS_REPLY_ARRAY)
                throw ConversionError("Redis reply was not an array!");
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
                throw ConversionError("Redis reply was not a string!");
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
            throw HiredisError(*context);
        m_redisContext = std::move(context);
    }

    void disconnect() noexcept { m_redisContext.reset(); }

    template <typename ... Args>
    Reply command(Args && ... args) {
        if (auto * reply = ::redisCommand(m_redisContext.get(),
                                          std::forward<Args>(args)...))
            return static_cast<::redisReply *>(reply);
        throw HiredisError(*m_redisContext);
    }

private: /* Fields: */

    ContextPtr m_redisContext;

};

inline SynchronousRedisClient & getClient(SharemindModuleApi0x1SyscallContext * c) {
    return getItem<SynchronousRedisClient>(c, "Client");
}

inline sharemind::ModuleData::HostConfiguration & getHostConf(SharemindModuleApi0x1SyscallContext * c) {
    return getItem<sharemind::ModuleData::HostConfiguration>(c, "HostConfiguration");
}

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
            // while the next response arrives store the prevoius response into set
            auto const replies(parts[1].asArray());
            for (auto & r : replies)
                keys.emplace(r.asString());
        } while (cursor);

        // Move all elements from keys to orderedKeys:
        for (auto & key : keys)
            orderedKeys.emplace_back(std::move(key));
    }

    std::vector<std::string> toDelete;
    if (sharemind::intersection(orderedKeys, toDelete, c)) {
        if (!toDelete.empty()) {
            std::ostringstream oss;
            oss << "DEL";
            for (auto const & key : toDelete)
                oss << ' ' << key;
            client.command(oss.str().c_str());
        }
        if (cleanUpOrderedKeys) {
            for (auto & k : toDelete) {
                auto it = std::lower_bound(orderedKeys.begin(), orderedKeys.end(), k);
                orderedKeys.erase(it);
            }
        }
        return true;
    }
    return false;
}

} /* namespace { */

SHAREMIND_DEFINE_SYSCALL(keydb_connect, 0, false, 0, 1,
        (void)args;

        if (crefs[0].size < 1)
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;

        auto * store = getDataStore(c, NS_KEYDB);

        if (store->get(store, "Client")) {
            mod.logger.error() << "You have already called keydb_connect!\n"
                               << "First call keydb_disconnect to drop the old connection.";
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
        }

        const std::string key(static_cast<char const * const>(crefs[0].pData), crefs[0].size - 1);
        auto it = mod.hostMap.find(key);
        if (it == mod.hostMap.end()) {
            mod.logger.error() << "Could not find the host \"" << key
                << "\" in the module hosts configuration.";
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
        }
        auto & hc = it->second;

        auto * client = new SynchronousRedisClient;
        auto deleter =
                [](void * const p) noexcept
                { delete static_cast<SynchronousRedisClient *>(p); };

        store->set(store, "Client", client, deleter);
        store->set(store, "HostConfiguration", &hc, nullptr);

        client->connect(hc.hostname, hc.port);
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
        if (args[0].uint64[0] > 1)
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
        if (crefs->size < 1)
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;

        bool isArray = args[0].uint64[0];

        if (isArray && crefs[1].size < 1)
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;

        const std::string key(static_cast<char const * const>(crefs[0].pData), crefs[0].size - 1);

        SHAREMIND_CHECK_PERMISSION(c, key, write);

        // arrays need size -1, scalars do not need it
        const std::string value(static_cast<char const * const>(crefs[1].pData), crefs[1].size - isArray);

        mod.logger.debug() << "Set with key \"" << key << "\" size = "
                           << value.size();

        auto const reply(getClient(c).command(
                             getHostConf(c).disableOverwrite
                             ? "SET %b %b NX"
                             : "SET %b %b",
                             static_cast<char const * const>(crefs[0].pData),
                             crefs[0].size - 1,
                             static_cast<char const * const>(crefs[1].pData),
                             crefs[1].size - isArray
                             ));
        if (reply.isError())
            mod.logger.error() << reply.errorString();
    );

SHAREMIND_DEFINE_SYSCALL(keydb_get_size, 1, true, 0, 1,
        (void) args;

        if (crefs->size < 1)
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;

        std::string const key(static_cast<char const * const>(crefs[0].pData),
                              crefs[0].size - 1);
        SHAREMIND_CHECK_PERMISSION(c, key, read);

        mod.logger.debug() << "keydb_get_size with key \"" << key << '\"';

        // store returned data in heap
        auto heapString(sharemind::makeUnique<std::string>(
                            getClient(c).command("GET %s",
                                                 key.c_str()).asString()));
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
            throw std::logic_error(
                    "Cannot get instance of data, was keydb_get_size called before?");

        mod.logger.debug() << "reference size, data size: "
            << refs[0].size << ", " << data->size();

        assert(refs[0].size == data->size() || refs[0].size == data->size()+1);
        // copy data to secrec
        memcpy(refs[0].pData, data->data(), data->size());

        // free data from heap
        store->remove(store, id);
    );

SHAREMIND_DEFINE_SYSCALL(keydb_del, 0, false, 0, 1,
        (void) args;

        if (crefs[0].size < 1)
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;

        std::string const key(static_cast<char const * const>(crefs[0].pData),
                              crefs[0].size - 1);
        SHAREMIND_CHECK_PERMISSION(c, key, write);
        getClient(c).command("DEL %b", key.c_str(), key.size());
    );

SHAREMIND_DEFINE_SYSCALL(keydb_scan, 0, true, 1, 1,
        (void) args;
        /** \todo It were easier and faster to take an uint64 argument and
                  return an uint64 instead of messing with references. */
        using ClCursor = std::uint64_t;
        assert(refs[0u].pData);
        if (refs[0u].size != sizeof(ClCursor))
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
        ClCursor const cl_cursor =
                [refs]() noexcept {
                    ClCursor r;
                    std::memcpy(&r, refs[0].pData, sizeof(r));
                    return r;
                }();

        auto * store = getDataStore(c, NS_SCAN);

        std::vector<std::string> * scan;
        char uid[21]; // 2^64 == 18 446 744 073 709 551 616
        if (cl_cursor) {
            std::sprintf(uid, "%" PRIu64, cl_cursor);
        } else {
            uid[0u] = '1';
            uid[1u] = '\0';
        }

        if (!cl_cursor) { // if a new cursor!
            if (crefs[0].size < 1u)
                return SHAREMIND_MODULE_API_0x1_INVALID_CALL;

            std::string const pattern(
                        static_cast<char const * const>(crefs[0u].pData),
                        crefs[0u].size - 1u);
            SHAREMIND_CHECK_PERMISSION(c, pattern, scan);

            ClCursor id = 1u;
            while (store->get(store, uid)) {
                ++id;
                std::sprintf(uid, "%" PRIu64, id);
            }
            auto newScan(sharemind::makeUnique<std::vector<std::string> >());
            static auto const deleter =
                    [](void * const p) noexcept
                    { delete static_cast<std::vector<std::string> *>(p); };
            if (!store->set(store, uid, newScan.get(), +deleter)) {
                newScan.release();
                /// \todo maybe should return something else? C interfaces... ;(
                return SHAREMIND_MODULE_API_0x1_OUT_OF_MEMORY;
            }
            scan = newScan.release();
            mod.logger.debug() << "keydb_scan: new cursor (" << uid << ')';
            std::memcpy(refs[0].pData, &id, sizeof(id));

            /* Run consensus because scan on redis does not guarantee order of
               keys: */
            scanAndClean(c, pattern.c_str(), *scan, true);
        } else { // existing cursor
            scan = static_cast<std::vector<std::string> *>(
                       store->get(store, uid));
        }

        /** \bug If the public allocations below fail, we essentially just skip
                 that element. This system call needs a better interface. */
        assert(scan);
        if (!scan->empty()) {
            auto const & data = scan->back();
            auto const mem_hndl = c->publicAlloc(c, data.size() + 1u);
            if (mem_hndl) {
                char * const ptr =
                        static_cast<char *>(c->publicMemPtrData(c, mem_hndl));
                std::memcpy(ptr, data.c_str(), data.size());
                // add the zero byte at the end
                *(ptr + data.size()) = '\0';
            }
            returnValue->uint64[0] = mem_hndl;
            scan->pop_back();
        } else {
            static ClCursor const zeroId = 0u;
            std::memcpy(refs[0].pData, &zeroId, sizeof(zeroId));
            auto const mem_hndl = c->publicAlloc(c, 1u);
            if (mem_hndl)
                (*static_cast<char *>(c->publicMemPtrData(c, mem_hndl))) = '\0';
            returnValue->uint64[0] = mem_hndl;
            store->remove(store, uid);
            mod.logger.debug() << "keydb_scan: del cursor (" << uid << ')';
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
