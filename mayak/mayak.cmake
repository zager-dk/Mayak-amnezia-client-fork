# Маяк: адрес шлюза подписки и его открытый ключ — генерируются в заголовок mayak_build.h.
# Ключ: переменная окружения PROD_AGW_PUBLIC_KEY (PEM) или файл mayak/gateway_public.pem.
# Свежий ключ всегда можно взять у сервиса: curl https://mayaklight.ru/gw/public-key

if(NOT MAYAK_GATEWAY_ENDPOINT)
    set(MAYAK_GATEWAY_ENDPOINT "https://mayaklight.ru/gw/" CACHE STRING "Mayak gateway endpoint (with trailing slash)")
endif()

set(_mayak_pem "$ENV{PROD_AGW_PUBLIC_KEY}")
if(_mayak_pem STREQUAL "" AND EXISTS "${CMAKE_SOURCE_DIR}/mayak/gateway_public.pem")
    file(READ "${CMAKE_SOURCE_DIR}/mayak/gateway_public.pem" _mayak_pem)
endif()
string(REPLACE "\r" "" _mayak_pem "${_mayak_pem}")
string(STRIP "${_mayak_pem}" _mayak_pem)
if(_mayak_pem STREQUAL "")
    message(FATAL_ERROR "Mayak: нет открытого ключа шлюза. Положите его в mayak/gateway_public.pem "
                        "(curl https://mayaklight.ru/gw/public-key > mayak/gateway_public.pem)")
endif()
if(NOT _mayak_pem MATCHES "^-----BEGIN PUBLIC KEY-----")
    message(FATAL_ERROR "Mayak: mayak/gateway_public.pem — не открытый ключ в формате PEM")
endif()

# Каждая строка PEM — отдельный строковый литерал с \n: так ключ попадает в программу без искажений.
string(REPLACE "\n" ";" _mayak_lines "${_mayak_pem}")
set(_mayak_literal "")
foreach(_l IN LISTS _mayak_lines)
    string(APPEND _mayak_literal "    \"${_l}\\n\" \\\n")
endforeach()

set(_mayak_header "// Сгенерировано mayak/mayak.cmake — не редактировать.\n#pragma once\n#define MAYAK_GATEWAY_ENDPOINT \"${MAYAK_GATEWAY_ENDPOINT}\"\n#define MAYAK_AGW_PUBLIC_KEY \\\n${_mayak_literal}    \"\"\n")
file(WRITE "${CMAKE_BINARY_DIR}/mayak/mayak_build.h.tmp" "${_mayak_header}")
file(COPY_FILE "${CMAKE_BINARY_DIR}/mayak/mayak_build.h.tmp" "${CMAKE_BINARY_DIR}/mayak/mayak_build.h" ONLY_IF_DIFFERENT)
include_directories("${CMAKE_BINARY_DIR}/mayak")
message(STATUS "Mayak: шлюз ${MAYAK_GATEWAY_ENDPOINT}")
