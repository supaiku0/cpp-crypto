cmake_minimum_required(VERSION 3.2.2)

project(Ark-Cpp-Crypto-tests)

hunter_add_package(GTest)
find_package(GTest CONFIG REQUIRED)

include(CTest)

set (PROJECT_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/../include)
set (PROJECT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set (CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../lib")

set(COVERAGE OFF CACHE BOOL "Coverage")

include_directories(${PROJECT_SOURCE_DIR}/../src)
include_directories(${PROJECT_SOURCE_DIR}/../include/bcl)
include_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})

set (TEST_SRC
	${PROJECT_SOURCE_DIR}/crypto/bip39.cpp
	${PROJECT_SOURCE_DIR}/crypto/crypto.cpp
	${PROJECT_SOURCE_DIR}/model/account.cpp
	${PROJECT_SOURCE_DIR}/model/block.cpp
	${PROJECT_SOURCE_DIR}/model/currency.cpp
	${PROJECT_SOURCE_DIR}/model/delegate.cpp
	${PROJECT_SOURCE_DIR}/model/fees.cpp
	${PROJECT_SOURCE_DIR}/model/network.cpp
	${PROJECT_SOURCE_DIR}/model/peer.cpp
	${PROJECT_SOURCE_DIR}/model/transaction.cpp
	${PROJECT_SOURCE_DIR}/model/voter.cpp
	${PROJECT_SOURCE_DIR}/types/address.cpp
	${PROJECT_SOURCE_DIR}/types/balance.cpp
	${PROJECT_SOURCE_DIR}/types/hash.cpp
	${PROJECT_SOURCE_DIR}/types/publickey.cpp
	${PROJECT_SOURCE_DIR}/types/signature.cpp
)

find_library(Ark-Cpp-Crypto-tests NAMES Ark-Cpp-Crypto-lib PATHS ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})

add_executable(Ark-Cpp-Crypto-tests ${TEST_SRC})

target_link_libraries(Ark-Cpp-Crypto-tests Ark-Cpp-Crypto-lib)

target_link_libraries(Ark-Cpp-Crypto-tests GTest::main) # GTest::gtest will be linked automatically
target_link_libraries(Ark-Cpp-Crypto-tests GTest::gtest)

if (COVERAGE)
	target_compile_options(tests PRIVATE --coverage)
	target_link_libraries(tests PRIVATE --coverage)
endif()

add_test(NAME test COMMAND Ark-Cpp-Crypto-tests)
