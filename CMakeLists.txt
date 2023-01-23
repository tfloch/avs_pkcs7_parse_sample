# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(pkcs7_parse)

target_sources(app PRIVATE src/main.c)

set(gen_dir ${ZEPHYR_BINARY_DIR}/include/generated/)

generate_inc_file_for_target(
    app
    data/good.pkcs7.der
    ${gen_dir}/good.pkcs7.der.inc
    )

generate_inc_file_for_target(
    app
    data/bad.pkcs7.der
    ${gen_dir}/bad.pkcs7.der.inc
    )

zephyr_include_directories(${APPLICATION_SOURCE_DIR}/src/tls_config)
