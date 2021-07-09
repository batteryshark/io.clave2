cmake_minimum_required(VERSION 3.16)
project(io_clave2 C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY  "${PROJECT_SOURCE_DIR}/../bin/")
set(CMAKE_SHARED_LIBRARY_PREFIX  "")
add_library(io_clave2 SHARED ../kitchen_sink/kitchen_sink.h ../kitchen_sink/target.h ../kitchen_sink/ks.debug.c ../kitchen_sink/ks.memutils.h ../kitchen_sink/ks.memutils.c ../kitchen_sink/ks.hotpatch.c ../kitchen_sink/ks.misc.c aes.c aes.h io.clave2.c io.clave2.emulator.c io.clave2.emulator.h io.clave2.hooks.c io.clave2.hooks.h io.clave2.protocol.c io.clave2.protocol.h)
set_target_properties(io_clave2 PROPERTIES COMPILE_FLAGS "-m32 -fshort-wchar" LINK_FLAGS "-m32 -fshort-wchar")
set_target_properties(io_clave2 PROPERTIES OUTPUT_NAME "io.clave2")


project(tools_io_clave2_test C)
add_executable(tools_io_clave2_test tools.io.clave2.test.c)
set_target_properties(tools_io_clave2_test PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
set_target_properties(tools_io_clave2_test PROPERTIES OUTPUT_NAME "tools.io.clave2.test")