/*!
 * defgroup sukat_api
 * @{
 */

Sukat Framework
===============

# Building

CMAKE is used for building. Create and build-directory, cmake and make.

```bash
mkdir build && cd build
cmake ../
make
```

To run unit tests, the -Dtest=ON should be defined. e.g.

```bash
mkdir build && cd build
cmake ../ -Dtest=ON && make && make test
```

note that unit tests need the google test library:
https://github.com/google/googletest

/*! }@ */
