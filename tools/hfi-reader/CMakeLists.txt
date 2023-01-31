cmake_minimum_required(VERSION 3.12)
project(hfi-reader)

add_executable(hfi-reader hfi-reader.c hfi-events.c)
target_compile_options(hfi-reader PRIVATE -Wall -O2)
target_include_directories(hfi-reader PRIVATE /usr/include/libnl3)
target_link_libraries(hfi-reader nl-3 nl-genl-3)
