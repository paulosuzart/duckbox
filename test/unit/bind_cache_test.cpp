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
        Expect(cache.Remember("k1", ipc), "bind key 1");
        Expect(cache.Remember("k2", ipc), "bind key 2");
        Expect(cache.Remember("k3", ipc), "bind key 3");
        Expect(cache.size() == 3, "up to three keys per bind are stored");
        const size_t want = (2 + ipc.size()) * 3;
        Expect(cache.bytes() == want, "byte budget counts every stored key, not one copy");
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
        constexpr int kCmpIters = 5000000;
        t0 = std::chrono::steady_clock::now();
        size_t rejects = 0;
        for (int i = 0; i < kCmpIters; i++) {
            rejects += static_cast<size_t>(last > kMaxBindParamsBytes);
        }
        auto cmp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                          std::chrono::steady_clock::now() - t0)
                          .count();
        Expect(rejects == 0, "measured ipc is under the max params size");
        std::cout << "doput_encode_without_size_check_us=" << without_us
                  << " doput_encode_with_size_check_us=" << with_us << " encode_iters=" << kIters
                  << " ipc_bytes=" << last << " size_check_only_ns=" << cmp_ns
                  << " size_check_iters=" << kCmpIters << "\n";
    }
}
