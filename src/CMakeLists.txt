
cmake_minimum_required(VERSION 3.2.2)

project(Ark-Cpp-Crypto-lib)

set (PROJECT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
 
include_directories(
	${PROJECT_SOURCE_DIR}
	${PROJECT_SOURCE_DIR}/bcl
	${PROJECT_SOURCE_DIR}/../include/uECC
)
 
set(COMMON_SRC 
	${PROJECT_SOURCE_DIR}/identities/privatekey.cpp
	${PROJECT_SOURCE_DIR}/identities/wif.cpp
	${PROJECT_SOURCE_DIR}/identities/publickey.cpp
	${PROJECT_SOURCE_DIR}/identities/address.cpp
)

set (BCL_SRC
	${PROJECT_SOURCE_DIR}/bcl/Base58Check.cpp
	${PROJECT_SOURCE_DIR}/bcl/CurvePoint.cpp
	${PROJECT_SOURCE_DIR}/bcl/Ecdsa.cpp
	${PROJECT_SOURCE_DIR}/bcl/FieldInt.cpp
	${PROJECT_SOURCE_DIR}/bcl/Ripemd160.cpp
	${PROJECT_SOURCE_DIR}/bcl/Sha256Hash.cpp
	${PROJECT_SOURCE_DIR}/bcl/Sha256.cpp
	${PROJECT_SOURCE_DIR}/bcl/Sha512.cpp
	${PROJECT_SOURCE_DIR}/bcl/Uint256.cpp
	${PROJECT_SOURCE_DIR}/bcl/Utils.cpp
)

set (uECC_SRC
	${PROJECT_SOURCE_DIR}/../include/uECC/uECC.c
)

add_library(Ark-Cpp-Crypto-lib STATIC ${COMMON_SRC} ${BCL_SRC} ${uECC_SRC})

if (MSVC)
	target_link_libraries(Ark-Cpp-Crypto-lib PUBLIC crypt32)
endif()
