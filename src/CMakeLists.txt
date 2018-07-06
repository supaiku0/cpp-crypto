
cmake_minimum_required(VERSION 3.2.2)

project(Ark-Cpp-Crypto-lib)

set (PROJECT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
 
include_directories(
	${PROJECT_SOURCE_DIR}
	${PROJECT_SOURCE_DIR}/../include/bcl
	${PROJECT_SOURCE_DIR}/../include/uECC
)
 
set(COMMON_SRC 
	${PROJECT_SOURCE_DIR}/crypto/ark_crypto.cpp
	${PROJECT_SOURCE_DIR}/crypto/bip39/bip39.cpp
	${PROJECT_SOURCE_DIR}/constants/networks.cpp
	${PROJECT_SOURCE_DIR}/models/one/account/account.cpp
	${PROJECT_SOURCE_DIR}/models/one/block/block.cpp
	${PROJECT_SOURCE_DIR}/models/one/currency/currency.cpp
	${PROJECT_SOURCE_DIR}/models/one/delegate/delegate.cpp
	${PROJECT_SOURCE_DIR}/models/one/fees/fees.cpp
	${PROJECT_SOURCE_DIR}/models/one/network/network.cpp
	${PROJECT_SOURCE_DIR}/models/one/peer/peer.cpp
	${PROJECT_SOURCE_DIR}/models/one/transaction/transaction.cpp
	${PROJECT_SOURCE_DIR}/models/one/voter/voter.cpp
	${PROJECT_SOURCE_DIR}/utilities/platform.cpp
)

set (BCL_SRC
	${PROJECT_SOURCE_DIR}/../include/bcl/Base58Check.cpp
	${PROJECT_SOURCE_DIR}/../include/bcl/CurvePoint.cpp
	${PROJECT_SOURCE_DIR}/../include/bcl/Ecdsa.cpp
	${PROJECT_SOURCE_DIR}/../include/bcl/FieldInt.cpp
	${PROJECT_SOURCE_DIR}/../include/bcl/Ripemd160.cpp
	${PROJECT_SOURCE_DIR}/../include/bcl/Sha256Hash.cpp
	${PROJECT_SOURCE_DIR}/../include/bcl/Sha256.cpp
	${PROJECT_SOURCE_DIR}/../include/bcl/Sha512.cpp
	${PROJECT_SOURCE_DIR}/../include/bcl/Uint256.cpp
	${PROJECT_SOURCE_DIR}/../include/bcl/Utils.cpp
)

set (uECC_SRC
	${PROJECT_SOURCE_DIR}/../include/uECC/uECC.c
)

add_library(Ark-Cpp-Crypto-lib STATIC ${COMMON_SRC} ${BCL_SRC} ${uECC_SRC})

if (MSVC)
	target_link_libraries(Ark-Cpp-Crypto-lib PUBLIC crypt32)
endif()
