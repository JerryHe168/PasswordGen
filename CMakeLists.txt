cmake_minimum_required(VERSION 3.10)

project(PasswordGen 
    VERSION 1.0.0 
    DESCRIPTION "一个功能完善的C++命令行密码生成器工具"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W3 /utf-8")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O2")
endif()

include_directories(include)

set(SOURCES
    src/main.cpp
    src/password_generator.cpp
    src/password_exporter.cpp
    src/argparse.cpp
)

add_executable(passwordgen ${SOURCES})

if(WIN32)
    target_compile_definitions(passwordgen PRIVATE -D_WIN32_WINNT=0x0601)
endif()

install(TARGETS passwordgen
    RUNTIME DESTINATION bin
)

option(BUILD_TESTS "Build unit tests" ON)

if(BUILD_TESTS)
    enable_testing()
    
    set(TEST_SOURCES
        tests/test_passwordgen.cpp
        src/password_generator.cpp
        src/password_exporter.cpp
    )
    
    add_executable(test_passwordgen ${TEST_SOURCES})
    
    target_include_directories(test_passwordgen PRIVATE include)
    
    if(WIN32)
        target_compile_definitions(test_passwordgen PRIVATE -D_WIN32_WINNT=0x0601)
    endif()
    
    add_test(NAME PasswordGenTests COMMAND test_passwordgen)
    
    message(STATUS "")
    message(STATUS "  测试:")
    message(STATUS "    构建测试:  是 (使用 -DBUILD_TESTS=OFF 禁用)")
    message(STATUS "    测试目标:  test_passwordgen")
endif()

message(STATUS "")
message(STATUS "========================================")
message(STATUS "  PasswordGen v${PROJECT_VERSION}")
message(STATUS "  C++密码生成器工具")
message(STATUS "========================================")
message(STATUS "")
message(STATUS "  编译选项:")
message(STATUS "    C++ 标准:  C++17")
message(STATUS "    编译器:    ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "")
