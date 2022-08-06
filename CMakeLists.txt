#
# Copyright (c) 20221 MINRES Technolgies GmbH
#
# SPDX-License-Identifier: Apache-2.0
#
cmake_minimum_required(VERSION 3.12)
project(dbt-rise-unicorn VERSION 0.0.1)
find_package(fmt)
add_library(${PROJECT_NAME}	src/unicorn_sc.cpp src/core_impl.cpp src/target_adapter.cpp)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_LIST_DIR}/src ${FMT_INCLUDE_DIRECTORIES})
target_link_directories(${PROJECT_NAME} PUBLIC  ${CMAKE_BINARY_DIR})
target_link_libraries(${PROJECT_NAME} PUBLIC unicorn dbt-rise-core SystemC::systemc)
