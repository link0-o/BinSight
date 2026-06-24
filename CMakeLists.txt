cmake_minimum_required(VERSION 3.24)

project(BinSight
  VERSION 0.1.0
  DESCRIPTION "Deterministic binary scanning with rule, RAG, and LLM risk analysis"
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(binsight_core
  src/binary_analyzer.cpp
  src/llm_client.cpp
  src/local_rag.cpp
  src/process_runner.cpp
  src/report_writer.cpp
  src/risk_rule_engine.cpp
  src/string_scanner.cpp
  src/types.cpp
  src/utils.cpp)
target_include_directories(binsight_core PUBLIC include)

add_executable(binsight src/main.cpp)
target_link_libraries(binsight PRIVATE binsight_core)

include(CTest)
if(BUILD_TESTING)
  add_executable(binsight_tests tests/unit_tests.cpp)
  target_link_libraries(binsight_tests PRIVATE binsight_core)
  add_test(NAME binsight_tests COMMAND binsight_tests)
  set_tests_properties(binsight_tests PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
endif()
