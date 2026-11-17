FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build libevent-dev python3 git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . /src
CMD ["sh", "-ec", "CC=cc tests/run-sni-tests.sh && cmake -S . -B /tmp/redsocks-build -G Ninja -DCMAKE_BUILD_TYPE=Debug '-DCMAKE_C_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer' && cmake --build /tmp/redsocks-build && python3 tests/test_http_connect_sni.py --binary /tmp/redsocks-build/redsocks"]
