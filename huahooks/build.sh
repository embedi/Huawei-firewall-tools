rm -f huahooks.so
mips64-linux-gnuabi64-gcc -g -O0 -fPIC -shared -o huahooks.so huahooks.c -ldl -lpthread