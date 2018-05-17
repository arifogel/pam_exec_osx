#!/bin/bash
set -e
./configure CFLAGS='-Wall -Wextra -Werror -Wno-unused-parameter -O0 -g'
make clean
make
make check
echo "Success! All tests passed."

