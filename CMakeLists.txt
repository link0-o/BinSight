cmake_minimum_required(VERSION 3.24)

project(BinSight
  VERSION 0.1.0
  DESCRIPTION "Deterministic binary scanning with rule, RAG, and LLM risk analysis"
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BINSIGHT_USE_LIEF "Enable the LIEF-backed parser dependency for release builds" OFF)

add_library(binsight_core
  src/binary_analyzer.cpp
  src/config.cpp
  src/llm_client.cpp
  src/local_rag.cpp
  src/process_runner.cpp
  src/report_writer.cpp
  src/risk_rule_engine.cpp
  src/string_scanner.cpp
  src/types.cpp
  src/utils.cpp)
target_include_directories(binsight_core PUBLIC include)
if(WIN32)
  target_link_libraries(binsight_core PUBLIC Advapi32)
endif()

if(BINSIGHT_USE_LIEF)
  include(FetchContent)
  set(LIEF_PYTHON_API OFF CACHE BOOL "" FORCE)
  set(LIEF_EXAMPLES OFF CACHE BOOL "" FORCE)
  set(LIEF_TESTS OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(
    LIEF
    GIT_REPOSITORY https://github.com/lief-project/LIEF.git
    GIT_TAG 0.16.6)
  FetchContent_MakeAvailable(LIEF)
  if(TARGET LIEF::LIEF)
    target_link_libraries(binsight_core PUBLIC LIEF::LIEF)
    target_compile_definitions(binsight_core PUBLIC BINSIGHT_USE_LIEF=1)
  elseif(TARGET LIB_LIEF)
    target_link_libraries(binsight_core PUBLIC LIB_LIEF)
    target_compile_definitions(binsight_core PUBLIC BINSIGHT_USE_LIEF=1)
  else()
    message(FATAL_ERROR "BINSIGHT_USE_LIEF is ON, but no LIEF CMake target was exported")
  endif()
endif()

add_executable(binsight src/main.cpp)
target_link_libraries(binsight PRIVATE binsight_core)

include(CTest)
if(BUILD_TESTING)
  add_executable(binsight_tests tests/unit_tests.cpp)
  target_link_libraries(binsight_tests PRIVATE binsight_core)
  add_test(NAME binsight_tests COMMAND binsight_tests)
  set_tests_properties(binsight_tests PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
endif()

include(GNUInstallDirs)
install(TARGETS binsight RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY rules knowledge docs DESTINATION .)
install(FILES README.md README.zh-CN.md LICENSE DESTINATION .)

set(CPACK_PACKAGE_NAME "BinSight")
set(CPACK_PACKAGE_VENDOR "BinSight")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_DESCRIPTION}")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${PROJECT_VERSION}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")
if(WIN32)
  set(CPACK_GENERATOR "ZIP")
else()
  set(CPACK_GENERATOR "TGZ")
endif()
include(CPack)
