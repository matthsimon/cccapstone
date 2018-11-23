cmake_minimum_required(VERSION 2.6)
project(capstone-c++)

set(VERSION_MAJOR 0)
set(VERSION_MINOR 1)

## TODO Manage optional build for different architectures

## sources
set(HEADER_BINDINGS
    cppbindings/ArmDisasm.hh
    cppbindings/CsCapstoneHelper.hh
    cppbindings/CsIns.hpp
    cppbindings/Disasm.hpp
    cppbindings/MipsDisasm.hh
    cppbindings/PPCDisasm.hh
    cppbindings/SparcDisasm.hh
    cppbindings/SystemZDisasm.hh
    cppbindings/X86Disasm.hh
    cppbindings/XCoreDisasm.hh
    )

## capstone sources
include_directories("${PROJECT_SOURCE_DIR}/capstone/include")
add_subdirectory(capstone)

## target
add_library(capstone-c++ SHARED ${HEADER_BINDINGS})
target_link_libraries(capstone-c++ capstone-static)
set_target_properties(capstone-c++ PROPERTIES LINKER_LANGUAGE CXX)

## installation
install(FILES ${HEADER_BINDINGS} DESTINATION include/capstone/cppbindings)
install(TARGETS capstone-c++
        LIBRARY DESTINATION lib)
