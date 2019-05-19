cmake_minimum_required (VERSION 2.6)
project (Tutorial)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/CMakeFiles")

file(GLOB sources server/*.cpp *.c)

find_package (PkgConfig REQUIRED)
pkg_check_modules (GIO REQUIRED gio-2.0)
pkg_check_modules (GLIB REQUIRED glib-2.0)
find_package (Threads)
find_package (LMDB REQUIRED)

include_directories (${GIO_INCLUDE_DIRS} ${GLIB_INCLUDE_DIRS} ${LMDB_INCLUDE_DIR})
link_directories (${GIO_LIBRARY_DIRS} ${GLIB_LIBRARY_DIRS})
add_definitions (${GIO_CFLAGS_OTHER} ${GLIB_CFLAGS_OTHER})

add_executable (main ${sources} main.cc)
target_link_libraries (main ${GLIB_LIBRARIES} ${GIO_LIBRARIES} ${LMDB_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
