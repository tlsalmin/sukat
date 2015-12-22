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
