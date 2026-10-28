#include "check.hpp"
#include "suite.hpp"

#include "flight/flight_sql_server.hpp"

#include <iostream>
#include <string>

void duckbox::test::RunBindCacheTests() {
    using duckbox::flight::BindCache;

    {
        BindCache cache(100);
        Expect(cache.max_bytes() == 100, "constructor sets the byte budget");
        Expect(cache.Remember("a", std::string(40, 'x')), "first entry fits");
        Expect(cache.Remember("b", std::string(40, 'y')), "second entry fits");
        Expect(cache.bytes() <= 100, "two entries stay under the budget");
        Expect(cache.size() == 2, "two keys stored");
        Expect(cache.Remember("c", std::string(40, 'z')), "third entry evicts the oldest");
        std::string v;
        Expect(!cache.Lookup("a", &v), "FIFO evicts the oldest key");
        Expect(cache.Lookup("b", &v) && v == std::string(40, 'y'), "middle key survives");
        Expect(cache.Lookup("c", &v) && v == std::string(40, 'z'), "newest key is stored");
        Expect(cache.bytes() <= 100, "eviction keeps the cache under the budget");
        Expect(cache.size() == 2, "evicted key is gone");
        Expect(cache.Consistent(), "list/map bookkeeping consistent after eviction");
    }

    {
        BindCache cache(100);
        const std::string ipc(20, 'p');
        Expect(cache.Remember("orig", ipc), "original handle is cached");
        Expect(cache.size() == 1, "one key per bind is stored");
        const size_t want = std::string("orig").size() + ipc.size();
        Expect(cache.bytes() == want, "byte budget counts the single stored key");
        Expect(cache.Remember("other", ipc), "a second bind is a separate key");
        Expect(cache.size() == 2, "independent binds are stored separately");
        Expect(cache.bytes() == want + std::string("other").size() + ipc.size(),
               "byte budget counts every stored key, not one copy");
    }

    {
        BindCache cache(10);
        Expect(!cache.Remember("k", std::string(20, 'x')),
               "entry larger than the budget is rejected");
        Expect(cache.size() == 0, "rejected entry is not stored");
        Expect(cache.bytes() == 0, "rejected entry does not consume the budget");
        std::string v;
        Expect(!cache.Lookup("k", &v), "rejected key is a miss");
    }

    {
        BindCache cache(50);
        Expect(cache.Remember("keep", std::string(10, 'a')), "seed entry");
        Expect(cache.Remember("k", std::string(20, 'b')), "second entry");
        Expect(cache.Remember("keep", std::string(10, 'c')), "update existing key");
        std::string v;
        Expect(cache.Lookup("keep", &v) && v == std::string(10, 'c'),
               "update replaces the payload");
        Expect(cache.Lookup("k", &v), "unrelated key remains");
        Expect(cache.bytes() <= 50, "update recounts bytes");
    }

    {
        BindCache cache(100);
        Expect(cache.Remember("a", std::string(49, 'x')), "boundary entry a");
        Expect(cache.Remember("b", std::string(49, 'y')), "entry that fills the budget exactly");
        Expect(cache.size() == 2 && cache.bytes() == 100,
               "bytes == max_bytes keeps both keys (no eviction at the boundary)");
        Expect(cache.Remember("c", ""), "one more byte");
        Expect(!cache.Lookup("a", nullptr) && cache.Lookup("b", nullptr) && cache.bytes() == 51,
               "one byte over the budget evicts exactly the oldest key");
    }

    {
        BindCache cache(10);
        Expect(cache.Remember("k", std::string(9, 'x')), "entry exactly at the budget is stored");
        Expect(cache.bytes() == 10 && cache.size() == 1, "entry at the budget is counted once");
    }

    {
        BindCache cache(50);
        Expect(cache.Remember("keep", std::string(10, 'a')), "overwrite seed");
        Expect(cache.Remember("k", std::string(20, 'b')), "overwrite second");
        Expect(cache.Remember("keep", std::string(10, 'c')), "overwrite existing key");
        Expect(cache.bytes() == 35 && cache.size() == 2,
               "overwrite recounts exactly (no double count)");
        Expect(cache.Remember("z", std::string(20, 'z')), "insert after overwrite");
        Expect(!cache.Lookup("k", nullptr) && cache.Lookup("keep", nullptr) && cache.bytes() == 35,
               "overwritten key moved to the back of the FIFO");
        Expect(cache.Consistent(), "list/map bookkeeping consistent after overwrite + eviction");
    }

    {
        BindCache cache(BindCache::kDefaultMaxBytes);
        size_t peak = 0;
        bool all_ok = true;
        for (int i = 0; i < 8000; i++) {
            if (!cache.Remember("k" + std::to_string(i), std::string(1024, 'm'))) {
                all_ok = false;
                break;
            }
            if (cache.bytes() > peak) {
                peak = cache.bytes();
            }
        }
        Expect(all_ok, "load insert stays within the budget");
        Expect(peak <= BindCache::kDefaultMaxBytes, "peak bytes stay at or under the budget");
        Expect(cache.bytes() <= BindCache::kDefaultMaxBytes, "bytes after load stay bounded");
        Expect(cache.Consistent(), "list/map bookkeeping consistent after load eviction");
        std::cout << "bind_cache_peak_bytes=" << peak
                  << " bind_cache_max_bytes=" << BindCache::kDefaultMaxBytes
                  << " bind_cache_entries=" << cache.size() << "\n";
    }
}
