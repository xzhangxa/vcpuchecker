cmake_minimum_required(VERSION 3.16)
project(vcpuchecker LANGUAGES C CXX)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/3rdparty/libbpf-bootstrap/cmake)

# Build vendored libbpf
include(ExternalProject)
ExternalProject_Add(libbpf
    PREFIX libbpf
    SOURCE_DIR ${PROJECT_SOURCE_DIR}/3rdparty/libbpf/src
    CONFIGURE_COMMAND mkdir -p ${PROJECT_BINARY_DIR}/libbpf/libbpf
    BUILD_COMMAND make
        BUILD_STATIC_ONLY=1
        OBJDIR=${PROJECT_BINARY_DIR}/libbpf/libbpf
        DESTDIR=${PROJECT_BINARY_DIR}/libbpf
        INCLUDEDIR=
        LIBDIR=
        UAPIDIR=
        install
    BUILD_IN_SOURCE TRUE
    INSTALL_COMMAND ""
    STEP_TARGETS build
)

ExternalProject_Add(bpftool
  PREFIX bpftool
  SOURCE_DIR ${PROJECT_SOURCE_DIR}/3rdparty/bpftool/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make OUTPUT=${PROJECT_BINARY_DIR}/bpftool/ BPF_DIR=${PROJECT_SOURCE_DIR}/3rdparty/libbpf/src bootstrap
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)

set(BPFOBJECT_VMLINUX_H ${PROJECT_SOURCE_DIR}/vmlinux/vmlinux.h)
set(BPFOBJECT_BPFTOOL_EXE ${PROJECT_BINARY_DIR}/bpftool/bootstrap/bpftool)
set(LIBBPF_INCLUDE_DIRS ${PROJECT_BINARY_DIR}/libbpf)
set(LIBBPF_LIBRARIES ${PROJECT_BINARY_DIR}/libbpf/libbpf.a)
find_package(BpfObject REQUIRED)

bpf_object(kvm_exit src/kvm_exit.bpf.c)
add_dependencies(kvm_exit_skel libbpf-build)
add_dependencies(kvm_exit_skel bpftool-build)

add_executable(${PROJECT_NAME} src/main.c src/display.cpp src/kvm_exit.c src/hfi.c)
target_include_directories(${PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/src /usr/include/libnl3)
target_compile_options(${PROJECT_NAME} PRIVATE -D_GNU_SOURCE -pthread)
target_link_libraries(${PROJECT_NAME} kvm_exit_skel virt nl-3 nl-genl-3)
