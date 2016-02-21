Sukat Framework
===============

# Building

CMAKE is used for building. Create and build-directory, cmake and make.

```bash
mkdir build && cd build
cmake ../
make


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
