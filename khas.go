sudo apt-get install git build-essential cmake libuv1-dev libssl-dev libhwloc-dev
mkdir build && cd build
cmake .. -DWITH_HTTPD=OFF
make
