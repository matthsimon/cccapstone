cmake_minimum_required(VERSION 2.6)
project(capstone-c++)
enable_testing()

set(VERSION_MAJOR 0)
set(VERSION_MINOR 1)

## TODO Manage optional build for different architectures

set(CMAKE_CXX_STANDARD 17)

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

## tests
find_package(Boost 1.63 REQUIRED COMPONENTS unit_test_framework)
set(BOOST_INCLUDE_DIRS $boost_installation_prefix/include)
add_executable(test_basic_cpp tests/test_basic.cc)
target_include_directories(test_basic_cpp PRIVATE ${BOOST_INCLUDE_DIRS}
    ${PROJECT_SOURCE_DIR}/cppbindings)
target_compile_definitions(test_basic_cpp PRIVATE "BOOST_TEST_DYN_LINK=1")
target_link_libraries(test_basic_cpp capstone-c++ ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY})
add_test(NAME test_basic_cpp COMMAND test_basic_cpp)
