cmake_minimum_required(VERSION 3.24)

project(BinSight
  VERSION 0.1.0
  DESCRIPTION "Deterministic binary scanning with rule, RAG, and LLM risk analysis"
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BINSIGHT_USE_LIEF "Enable the LIEF-backed production PE/ELF parser" ON)
set(BINSIGHT_BUILD_GUI "AUTO" CACHE STRING "Build the Qt Widgets GUI: AUTO, ON, or OFF")
set_property(CACHE BINSIGHT_BUILD_GUI PROPERTY STRINGS AUTO ON OFF)

add_library(binsight_core
  src/binary_analyzer.cpp
  src/config.cpp
  src/dynamic_observer.cpp
  src/llm_client.cpp
  src/local_rag.cpp
  src/process_runner.cpp
  src/report_writer.cpp
  src/risk_rule_engine.cpp
  src/scan_pipeline.cpp
  src/string_scanner.cpp
  src/types.cpp
  src/utils.cpp)
target_include_directories(binsight_core PUBLIC include)
if(WIN32)
  target_link_libraries(binsight_core PUBLIC Advapi32)
endif()

if(BINSIGHT_USE_LIEF)
  find_package(LIEF CONFIG QUIET)
  if(NOT TARGET LIEF::LIEF AND NOT TARGET LIB_LIEF)
    include(FetchContent)
    set(LIEF_PYTHON_API OFF CACHE BOOL "" FORCE)
    set(LIEF_C_API OFF CACHE BOOL "" FORCE)
    set(LIEF_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(LIEF_TESTS OFF CACHE BOOL "" FORCE)
    set(LIEF_USE_CCACHE OFF CACHE BOOL "" FORCE)
    set(LIEF_ENABLE_JSON OFF CACHE BOOL "" FORCE)
    set(LIEF_ELF ON CACHE BOOL "" FORCE)
    set(LIEF_PE ON CACHE BOOL "" FORCE)
    set(LIEF_COFF ON CACHE BOOL "" FORCE)
    set(LIEF_MACHO OFF CACHE BOOL "" FORCE)
    set(LIEF_DEX OFF CACHE BOOL "" FORCE)
    set(LIEF_ART OFF CACHE BOOL "" FORCE)
    set(LIEF_OAT OFF CACHE BOOL "" FORCE)
    set(LIEF_VDEX OFF CACHE BOOL "" FORCE)
    set(LIEF_DEBUG_INFO OFF CACHE BOOL "" FORCE)
    set(LIEF_OBJC OFF CACHE BOOL "" FORCE)
    set(LIEF_DYLD_SHARED_CACHE OFF CACHE BOOL "" FORCE)
    set(LIEF_ASM OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(
      LIEF
      GIT_REPOSITORY https://github.com/lief-project/LIEF.git
      GIT_TAG 0.17.6)
    FetchContent_MakeAvailable(LIEF)
  endif()
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

string(TOUPPER "${BINSIGHT_BUILD_GUI}" BINSIGHT_BUILD_GUI_UPPER)
if(NOT BINSIGHT_BUILD_GUI_UPPER STREQUAL "OFF")
  find_package(Qt6 COMPONENTS Widgets QUIET)
  if(Qt6_FOUND)
    add_executable(binsight-gui src/gui/main.cpp)
    target_link_libraries(binsight-gui PRIVATE binsight_core Qt6::Widgets)
    target_compile_definitions(binsight-gui PRIVATE QT_NO_KEYWORDS)
  elseif(BINSIGHT_BUILD_GUI_UPPER STREQUAL "ON")
    message(FATAL_ERROR "BINSIGHT_BUILD_GUI=ON requires Qt6 Widgets. Install Qt 6 or use -DBINSIGHT_BUILD_GUI=OFF.")
  else()
    message(STATUS "Qt6 Widgets not found; skipping binsight-gui")
  endif()
endif()

include(CTest)
if(BUILD_TESTING)
  add_executable(binsight_tests tests/unit_tests.cpp)
  target_link_libraries(binsight_tests PRIVATE binsight_core)
  add_test(NAME binsight_tests COMMAND binsight_tests)
  set_tests_properties(binsight_tests PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
endif()

include(GNUInstallDirs)
install(TARGETS binsight RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
if(TARGET binsight-gui)
  install(TARGETS binsight-gui RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
  if(COMMAND qt_generate_deploy_app_script)
    qt_generate_deploy_app_script(
      TARGET binsight-gui
      OUTPUT_SCRIPT BINSIGHT_GUI_DEPLOY_SCRIPT
      NO_UNSUPPORTED_PLATFORM_ERROR)
    install(SCRIPT ${BINSIGHT_GUI_DEPLOY_SCRIPT})
  endif()
endif()
install(DIRECTORY rules knowledge docs docker DESTINATION .)
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
