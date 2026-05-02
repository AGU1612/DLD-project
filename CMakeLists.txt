cmake_minimum_required(VERSION 3.13)

set(PICO_SDK_PATH "C:/Program Files/Raspberry Pi/Pico SDK v1.5.1/pico-sdk")

include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)

project(pico_project C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

add_executable(pico_project
    main.c
    mfrc522.c
)

target_link_libraries(pico_project pico_stdlib hardware_spi pico_multicore)

pico_add_extra_outputs(pico_project)
pico_enable_stdio_usb(pico_project 1)
pico_enable_stdio_uart(pico_project 0)