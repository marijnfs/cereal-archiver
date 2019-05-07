all:
	clang++ -g -std=c++17 `pkg-config --libs --cflags glib-2.0`  `pkg-config --libs --cflags gio-2.0` -llmdb main.cc blake2b.c

