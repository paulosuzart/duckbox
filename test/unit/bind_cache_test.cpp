#include "check.hpp"
#include "suite.hpp"

#include "flight/flight_sql_server.hpp"

#include <arrow/array.h>
#include <arrow/builder.h>
#include <arrow/io/memory.h>
#include <arrow/ipc/writer.h>
#include <arrow/record_batch.h>
#include <arrow/table.h>
#include <arrow/type.h>

#include <chrono>
#include <iostream>
#include <string>

void duckbox::test::RunBindCacheTests() {
    using duckbox::flight::BindCache;
    using duckbox::flight::kMaxBindParamsBytes;

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
        std::cout << "bind_cache_peak_bytes=" << peak
                  << " bind_cache_max_bytes=" << BindCache::kDefaultMaxBytes
                  << " bind_cache_entries=" << cache.size() << "\n";
    }

    {
        constexpr int n = 15000;
        constexpr size_t payload = 64;
        const size_t budget = static_cast<size_t>(n) * (16 + payload);
        BindCache cache(budget);
        bool all_ok = true;
        auto t0 = std::chrono::steady_clock::now();
        for (int i = 0; i < n; i++) {
            if (!cache.Remember("k" + std::to_string(i), std::string(payload, 'm'))) {
                all_ok = false;
                break;
            }
        }
        auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                      std::chrono::steady_clock::now() - t0)
                      .count();
        Expect(all_ok && cache.size() == static_cast<size_t>(n),
               "15k unique inserts stay in the cache");
        size_t keys = 0;
        for (int i = 0; i < n; i++) {
            keys += ("k" + std::to_string(i)).size();
        }
        Expect(cache.bytes() == cache.size() * payload + keys,
               "15k insert byte accounting is exact");
        t0 = std::chrono::steady_clock::now();
        bool over_ok = true;
        for (int i = 0; i < 1000; i++) {
            if (!cache.Remember("k" + std::to_string(i), std::string(payload, 'n'))) {
                over_ok = false;
                break;
            }
        }
        auto over_us = std::chrono::duration_cast<std::chrono::microseconds>(
                           std::chrono::steady_clock::now() - t0)
                           .count();
        Expect(over_ok && cache.size() == static_cast<size_t>(n),
               "overwrite of 1000 existing keys at 15k stays exact");
        std::cout << "bind_cache_insert_15k_us=" << us
                  << " bind_cache_overwrite_1k_at_15k_us=" << over_us
                  << " bind_cache_entries=" << cache.size() << "\n";
    }

    {
        ::arrow::Int32Builder b;
        Expect(b.Append(1).ok(), "measure bind append");
        std::shared_ptr<::arrow::Array> arr;
        Expect(b.Finish(&arr).ok(), "measure bind finish");
        auto batch = ::arrow::RecordBatch::Make(
            ::arrow::schema({::arrow::field("$1", ::arrow::int32())}), 1, {arr});
        auto table = ::arrow::Table::FromRecordBatches({batch}).ValueOrDie();
        auto encode = [&]() -> size_t {
            auto sink = ::arrow::io::BufferOutputStream::Create().ValueOrDie();
            auto w = ::arrow::ipc::MakeStreamWriter(sink, table->schema()).ValueOrDie();
            Expect(w->WriteTable(*table).ok(), "measure encode write");
            Expect(w->Close().ok(), "measure encode close");
            auto ipc = sink->Finish().ValueOrDie();
            return static_cast<size_t>(ipc->size());
        };
        constexpr int kWarm = 50;
        constexpr int kIters = 400;
        size_t last = 0;
        for (int i = 0; i < kWarm; i++) {
            last = encode();
        }
        auto t0 = std::chrono::steady_clock::now();
        for (int i = 0; i < kIters; i++) {
            last = encode();
        }
        auto without_us = std::chrono::duration_cast<std::chrono::microseconds>(
                              std::chrono::steady_clock::now() - t0)
                              .count();
        t0 = std::chrono::steady_clock::now();
        int accepted = 0;
        for (int i = 0; i < kIters; i++) {
            last = encode();
            if (last <= kMaxBindParamsBytes) {
                accepted++;
            }
        }
        auto with_us = std::chrono::duration_cast<std::chrono::microseconds>(
                           std::chrono::steady_clock::now() - t0)
                           .count();
        Expect(accepted == kIters, "measured binds are under the max params size");
        std::cout << "doput_encode_without_size_check_us=" << without_us
                  << " doput_encode_with_size_check_us=" << with_us << " encode_iters=" << kIters
                  << " ipc_bytes=" << last << "\n";
    }
}
