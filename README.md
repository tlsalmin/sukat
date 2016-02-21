Sukat Framework
===============

# Building

CMAKE is used for building. Create and build-directory, cmake and make.

```bash
mkdir build && cd build
cmake ../
make
```


## Unit tests.

To run unit tests, the -Dtest=ON should be defined. e.g.

```bash
mkdir build && cd build
cmake ../ -Dtest=ON && make && make test
```
note that unit tests need the google test library:
https://github.com/google/googletest

## Coverage

To run coverage results the -Dcoverage=ON should be defined.
```bash
mkdir build && cd build
cmake ../ -DCMAKE_BUILD_TYPE=Debug -Dcoverage=ON && make && make sukat_sock_coverage
```

## Doxygen

To generate the doxygen documentation:
```bash
mkdir build && cd build
cmake ../ && make && make doc
```

## Benchmarks

To build google benchmarks also:
```bash
mkdir build && cd build
cmake ../ -Dbenchmark=ON && make
```

This will create the benchmarks/benchmark_sock binary, which right now tests
socket creation and message sending between AF_UNIX, AF_INET, AF_INET6 and
types SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET.

### Example for benchmarks
```bash
Run on (4 X 3300 MHz CPU s)
2016-02-21 15:35:55
***WARNING*** CPU scaling is enabled, the benchmark real time measurements may be noisy and will incure extra overhead.
***WARNING*** Library was built as DEBUG. Timings may be affected.
Benchmark                      Time(ns)    CPU(ns) Iterations
-------------------------------------------------------------
SockFixture/sock_create/2/1        8815       8597      82353
SockFixture/sock_create/2/2        5837       5643     122807
SockFixture/sock_create/10/1       9445       9231      78652
SockFixture/sock_create/10/2       6299       6091     114754
stream_and_domains/8/2        546894250  546500000          2  11.8464MB/s
stream_and_domains/64/2        61899860   61900000         10  89.5853MB/s
stream_and_domains/512/2        6490188    6490741        108  623.787MB/s
stream_and_domains/4k/2         1595797    1594966        437  2.48527GB/s
stream_and_domains/8k/2         1256635    1255396        556  3.15814GB/s
stream_and_domains/8/10       550427802  550000000          2  11.7677MB/s
stream_and_domains/64/10       62647420   62600000         10  89.2439MB/s
stream_and_domains/512/10       6498251    6490741        108  623.904MB/s
stream_and_domains/4k/10        1595577    1593607        438  2.48526GB/s
stream_and_domains/8k/10        1258907    1257194        556  3.15361GB/s
stream_and_domains/8/1           267232     267228       2612  7.93693MB/s
stream_and_domains/64/1          278113     277997       2536  61.0358MB/s
stream_and_domains/512/1         181260     181023       3889  450.455MB/s
stream_and_domains/4k/1           78301      78208       8861  2.14616GB/s
stream_and_domains/8k/1           60629      60598      11667  3.02163GB/s
unix_and_types/8/1               266821     266590       2622  7.95592MB/s
unix_and_types/64/1              275859     276025       2536  61.4718MB/s
unix_and_types/512/1             180538     180502       3867  451.757MB/s
unix_and_types/4k/1               81627      81593       8861  2.05711GB/s
unix_and_types/8k/1               60170      60131      11475  3.04512GB/s
unix_and_types/8/2                44991      43162      16241  1.94436MB/s
unix_and_types/64/2               45176      43347      16241  15.4886MB/s
unix_and_types/512/2              45665      43763      16018  122.731MB/s
unix_and_types/4k/2               49254      47364      14737  907.207MB/s
unix_and_types/8k/2               57247      55394      12727  1.51502GB/s
unix_and_types/8/5               398893     398857       1750  5.31762MB/s
unix_and_types/64/5              408050     407599       1737  41.6286MB/s
unix_and_types/512/5             247965     247963       2823  328.851MB/s
unix_and_types/4k/5               45862      45831      15317  2.16406GB/s
unix_and_types/8k/5               30297      30257      23102  3.27798GB/s

```

Its kinda annoying that the domains and types are show as numbers. Maybe the
value could be passed as a string and interpreted.
