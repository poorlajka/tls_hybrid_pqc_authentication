#[[
    For configuring the settings add_definitions was used for the schemes
    which build directly with cmake. For those requiring running a makefile set some variables instead
    that get handled in the respective subfolder.
]]

set (NIST_SEC_CATS 1 3 5)

if (NOT NIST_SEC_CAT IN_LIST NIST_SEC_CATS)
    message(FATAL_ERROR "NIST_SEC_CAT is not correctly defined! Should be one of ${NIST_SEC_CATS}")
endif()

if (NIST_SEC_CAT EQUAL 1)
    set(MAYO_SEC_LEVEL "1") 
    set(CROSS_SEC_LEVEL "1") 
    set(SDITH_SEC_LEVEL "cat1")
    set(SQISIGN_SEC_LEVEL "lvl1")
    set(MIRATH_SEC_LEVEL "1") 
    set(PERK_SEC_LEVEL "128") 
    set(RYDE_SEC_LEVEL "1") 
    set(MQOM_SEC_LEVEL "cat1") 
    set(FALCON_SEC_LEVEL "512") 
    set(DILITHIUM_SEC_LEVEL "2") 
    set(SPHINCS_SEC_LEVEL "128") 
    set(HAWK_SEC_LEVEL "512") 

    set(FAEST_SEC_LEVEL "128") 

    set(SNOVA_V 24)
    set(SNOVA_O 5)
    set(SNOVA_L 4)

    set(QRUOV_security_strength_category 1)
    set(QRUOV_q 31)
    set(QRUOV_v 600)
    set(QRUOV_m 70)
    set(QRUOV_L 10)

    set(UOV_PARAM 2)
    
    # LESS
    add_definitions(
        -DCATEGORY=252
        -DTARGET=192
    )

elseif(NIST_SEC_CAT EQUAL 3)
    set(MAYO_SEC_LEVEL "3") 
    set(CROSS_SEC_LEVEL "3") 
    set(SDITH_SEC_LEVEL "cat3")
    set(SQISIGN_SEC_LEVEL "lvl3")
    set(MIRATH_SEC_LEVEL "3") 
    set(PERK_SEC_LEVEL "192") 
    set(RYDE_SEC_LEVEL "3") 
    set(MQOM_SEC_LEVEL "cat3") 
    set(FALCON_SEC_LEVEL "1024") 
    set(DILITHIUM_SEC_LEVEL "3") 
    set(SPHINCS_SEC_LEVEL "192") 
    set(HAWK_SEC_LEVEL "1024") 

    set(FAEST_SEC_LEVEL "192") 

    set(SNOVA_V 24)
    set(SNOVA_O 5)
    set(SNOVA_L 5)

    set(QRUOV_security_strength_category 3)
    set(QRUOV_q 31)
    set(QRUOV_v 890)
    set(QRUOV_m 100)
    set(QRUOV_L 10)

    set(UOV_PARAM 4)

    # LESS
    add_definitions(
        -DCATEGORY=400
        -DTARGET=220
    )

elseif(NIST_SEC_CAT EQUAL 5)
    set(MAYO_SEC_LEVEL "5") 
    set(CROSS_SEC_LEVEL "5") 
    set(SDITH_SEC_LEVEL "cat5")
    set(SQISIGN_SEC_LEVEL "lvl5")
    set(MIRATH_SEC_LEVEL "5") 
    set(PERK_SEC_LEVEL "256") 
    set(RYDE_SEC_LEVEL "5") 
    set(MQOM_SEC_LEVEL "cat5") 
    set(FALCON_SEC_LEVEL "1024") 
    set(DILITHIUM_SEC_LEVEL "5") 
    set(SPHINCS_SEC_LEVEL "256") 
    set(HAWK_SEC_LEVEL "1024") 

    set(FAEST_SEC_LEVEL "256") 

    set(SNOVA_V 29)
    set(SNOVA_O 6)
    set(SNOVA_L 5)

    set(QRUOV_security_strength_category 5)
    set(QRUOV_q 31)
    set(QRUOV_v 1120)
    set(QRUOV_m 120)
    set(QRUOV_L 10)

    set(UOV_PARAM 5)

    # LESS
    add_definitions(
        -DCATEGORY=548
        -DTARGET=345
    )
endif ()

#[[ 
    MAYO Settings
]]
set(MAYO_BUILD_TYPE "AVX2") 

set(MAYO_BUILD_TYPES "REF" "AVX2") 
if(NOT MAYO_BUILD_TYPE IN_LIST MAYO_BUILD_TYPES)
    message(FATAL_ERROR "MAYO_BUILD_TYPE is not correctly defined! Should be one of ${MAYO_BUILD_TYPES}")
endif()

set(MAYO_SEC_LEVELS "1" "2" "3" "5") 
if(NOT MAYO_SEC_LEVEL IN_LIST MAYO_SEC_LEVELS)
    message(FATAL_ERROR "MAYO_SEC_LEVEL is not correctly defined! Should be one of ${MAYO_SEC_LEVELS}")
endif()

#[[ 
    LESS settings
]]
add_definitions(
    -DUSE_AVX2
)

#[[ 
    CROSS Settings
]]
set(CROSS_VARIANT "RSDPG") 
set(CROSS_BALANCE "SIG_SIZE") 

set(CROSS_SEC_LEVELS "1" "3" "5") 
if(NOT CROSS_SEC_LEVEL IN_LIST CROSS_SEC_LEVELS)
    message(FATAL_ERROR "CROSS_SEC_LEVEL is not correctly defined! Should be one of ${CROSS_SEC_LEVELS}")
endif()

set(CROSS_BALANCES "SPEED" "BALANCE" "SIG_SIZE") 
if(NOT CROSS_BALANCE IN_LIST CROSS_BALANCES)
    message(FATAL_ERROR "CROSS_BALANCE is not correctly defined! Should be one of ${CROSS_BALANCES}")
endif()

set(CROSS_VARIANTS "RSDP" "RSDPG")
if(NOT CROSS_VARIANT IN_LIST CROSS_VARIANTS)
    message(FATAL_ERROR "CROSS_VARIANT is not correctly defined! Should be one of ${CROSS_VARIANTS}")
endif()

# Need to be set here and not in the CROSS CMakeLists.txt for god knows what reason, idc for now 
add_definitions(
    -D${CROSS_VARIANT}
    -DCATEGORY_${CROSS_SEC_LEVEL}
    -D${CROSS_BALANCE}
)

#[[ 
    QRUOV settings
]]
set(QRUOV_OPTIMISATION "avx2") # ref|avx2|avx512|portable64
set(QRUOV_CONFIG_H_GEN 1)
set(QRUOV_fc 1)
set(QRUOV_fe 1)
set(QRUOV_fc0 1)
set(QRUOV_PRG "a")

# SNOVA settings
set(SNOVA_SK_IS_SEED 0) # Use seed as secret key 
set(SNOVA_OPTIMISATION 2) # 0 = Reference, 1 = General optimization, 2 = AVX2 Optimization 
set(SNOVA_PK_EXPAND_SHAKE 0) # Use SHAKE128 for public key expansion instead of AES-CTR(Disabled for now)

#[[ 
    UOV settings
    TODO: For some reason this doesn't build correctly with param > 3.
    The reason for this eludes me.
]]
set(UOV_PROJ avx2)
set(UOV_VARIANT 1)

#[[ 
    SDITH settings
]]
set(SDITH_VARIANT "Optimized_Implementation") # ref|avx2 
set(SDITH_TYPE "Hypercube_Variant") # Threshhold_Variant|Hypercube_Variant
set(SDITH_FIELD "gf256") # GF256|P251

set(SDITH_SEC_LEVELS "cat1" "cat3" "cat5")
if(NOT SDITH_SEC_LEVEL IN_LIST SDITH_SEC_LEVELS)
    message(FATAL_ERROR "SDITH_SEC_LEVEL is not correctly defined! Should be one of ${SDITH_SEC_LEVELS}")
endif()

set(SDITH_VARIANTS "Reference_Implementation" "Optimized_Implementation")
if(NOT SDITH_VARIANT IN_LIST SDITH_VARIANTS)
    message(FATAL_ERROR "SDITH_VARIANT is not correctly defined! Should be one of ${SDITH_VARIANTs}")
endif()

set(SDITH_TYPES "Hypercube_Variant" "Threshhold_Variant")
if(NOT SDITH_TYPE IN_LIST SDITH_TYPES)
    message(FATAL_ERROR "SDITH_TYPE is not correctly defined! Should be one of ${SDITH_TYPES}")
endif()

set(SDITH_FIELDS "gf256" "p251")
if(NOT SDITH_FIELD IN_LIST SDITH_FIELDS)
    message(FATAL_ERROR "SDITH_FIELD is not correctly defined! Should be one of ${SDITH_FIELDS}")
endif()

#[[ 
    SQISIGN Settings
]]
set(SQISIGN_BUILD_TYPE "broadwell")

set(SQISIGN_SEC_LEVELS "lvl1" "lvl3" "lvl5")
if(NOT SQISIGN_SEC_LEVEL IN_LIST SQISIGN_SEC_LEVELS)
    message(FATAL_ERROR "SQISIGN_SEC_LEVEL is not correctly defined! Should be one of ${SQISIGN_SEC_LEVELS}")
endif()

set(SQISIGN_BUILD_TYPES "ref" "opt" "broadwell" "arm64crypto")
if(NOT SQISIGN_BUILD_TYPE IN_LIST SQISIGN_BUILD_TYPES)
    message(FATAL_ERROR "SQISIGN_BUILD_TYPE is not correctly defined! Should be one of ${SQISIGN_BUILD_TYPES}")
endif()

#[[ 
    MIRATH Settings
]]
set(MIRATH_BUILD_TYPE "opt") 
set(MIRATH_BALANCE "short") 
set(MIRATH_Q "b") 

set(MIRATH_BUILD_TYPES "ref" "opt") 
if(NOT MIRATH_BUILD_TYPE IN_LIST MIRATH_BUILD_TYPES)
    message(FATAL_ERROR "MIRATH_BUILD_TYPE is not correctly defined! Should be one of ${MIRATH_BUILD_TYPES}")
endif()

set(MIRATH_SEC_LEVELS "1" "3" "5") 
if(NOT MIRATH_SEC_LEVEL IN_LIST MIRATH_SEC_LEVELS)
    message(FATAL_ERROR "MIRATH_SEC_LEVEL is not correctly defined! Should be one of ${MIRATH_SEC_LEVELS}")
endif()

set(MIRATH_BALANCES "fast" "short") 
if(NOT MIRATH_BALANCE IN_LIST MIRATH_BALANCES)
    message(FATAL_ERROR "MIRATH_BALANCE is not correctly defined! Should be one of ${MIRATH_BALANCES}")
endif()

set(MIRATH_QS "a" "b") 
if(NOT MIRATH_Q IN_LIST MIRATH_QS)
    message(FATAL_ERROR "MIRATH_Q is not correctly defined! Should be one of ${MIRATH_QS}")
endif()

#[[ 
    PERK Settings
]]
set(PERK_BUILD_TYPE "opt") 
set(PERK_BALANCE "short") 
set(PERK_VARIANT "5") #TODO: DECIDE IF THIS SHOULD BE 3 or 5!

set(PERK_BUILD_TYPES "ref" "opt") 
if(NOT PERK_BUILD_TYPE IN_LIST PERK_BUILD_TYPES)
    message(FATAL_ERROR "PERK_BUILD_TYPE is not correctly defined! Should be one of ${PERK_BUILD_TYPES}")
endif()

set(PERK_SEC_LEVELS "128" "192" "256") # 1 | 3 | 5
if(NOT PERK_SEC_LEVEL IN_LIST PERK_SEC_LEVELS)
    message(FATAL_ERROR "PERK_SEC_LEVEL is not correctly defined! Should be one of ${PERK_SEC_LEVELS}")
endif()

set(PERK_BALANCES "fast" "short") 
if(NOT PERK_BALANCE IN_LIST PERK_BALANCES)
    message(FATAL_ERROR "PERK_BALANCE is not correctly defined! Should be one of ${PERK_BALANCES}")
endif()

set(PERK_VARIANTS "3" "5") 
if(NOT PERK_VARIANT IN_LIST PERK_VARIANTS)
    message(FATAL_ERROR "PERK_VARIANT is not correctly defined! Should be one of ${PERK_VARIANTS}")
endif()

#[[ 
    RYDE Settings
]]
set(RYDE_BUILD_TYPE "opt") 
set(RYDE_BALANCE "s") 
set(RYDE_COMMIT_GEN "rijndael") 

set(RYDE_BUILD_TYPES "ref" "opt") 
if(NOT RYDE_BUILD_TYPE IN_LIST RYDE_BUILD_TYPES)
    message(FATAL_ERROR "RYDE_BUILD_TYPE is not correctly defined! Should be one of ${RYDE_BUILD_TYPES}")
endif()

set(RYDE_SEC_LEVELS "1" "3" "5") 
if(NOT RYDE_SEC_LEVEL IN_LIST RYDE_SEC_LEVELS)
    message(FATAL_ERROR "RYDE_SEC_LEVEL is not correctly defined! Should be one of ${RYDE_SEC_LEVELS}")
endif()

set(RYDE_BALANCES "f" "s") 
if(NOT RYDE_BALANCE IN_LIST RYDE_BALANCES)
    message(FATAL_ERROR "RYDE_BALANCE is not correctly defined! Should be one of ${RYDE_BALANCES}")
endif()

set(RYDE_COMMIT_GENS "rijndael" "sha3") 
if(NOT RYDE_COMMIT_GEN IN_LIST RYDE_COMMIT_GENS)
    message(FATAL_ERROR "RYDE_COMMIT_GEN is not correctly defined! Should be one of ${RYDE_COMMIT_GENS}")
endif()

#[[ 
    MQOM Settings
]]
set(MQOM_BUILD_TYPE "opt") 
set(MQOM_BALANCE "short") 
set(MQOM_BASE_FIELD "gf2") 
set(MQOM_VARIANT "r5") 

set(MQOM_BUILD_TYPES "ref" "opt") 
if(NOT MQOM_BUILD_TYPE IN_LIST MQOM_BUILD_TYPES)
    message(FATAL_ERROR "MQOM_BUILD_TYPE is not correctly defined! Should be one of ${MQOM_BUILD_TYPES}")
endif()

set(MQOM_SEC_LEVELS "cat1" "cat3" "cat5") 
if(NOT MQOM_SEC_LEVEL IN_LIST MQOM_SEC_LEVELS)
    message(FATAL_ERROR "MQOM_SEC_LEVEL is not correctly defined! Should be one of ${MQOM_SEC_LEVELS}")
endif()

set(MQOM_BALANCES "fast" "short") 
if(NOT MQOM_BALANCE IN_LIST MQOM_BALANCES)
    message(FATAL_ERROR "MQOM_BALANCE is not correctly defined! Should be one of ${MQOM_BALANCES}")
endif()

set(MQOM_BASE_FIELDS "gf2" "gf256") 
if(NOT MQOM_BASE_FIELD IN_LIST MQOM_BASE_FIELDS)
    message(FATAL_ERROR "MQOM_BASE_FIELD is not correctly defined! Should be one of ${MQOM_BASE_FIELDS}")
endif()

set(MQOM_VARIANTS "r3" "r5") 
if(NOT MQOM_VARIANT IN_LIST MQOM_VARIANTS)
    message(FATAL_ERROR "MQOM_VARIANT is not correctly defined! Should be one of ${MQOM_VARIANTS}")
endif()

#[[ 
    FALCON Settings
]]
set(FALCON_BUILD_TYPE "opt") 

set(FALCON_BUILD_TYPES "ref" "opt") 
if(NOT FALCON_BUILD_TYPE IN_LIST FALCON_BUILD_TYPES)
    message(FATAL_ERROR "FALCON_BUILD_TYPE is not correctly defined! Should be one of ${FALCON_BUILD_TYPES}")
endif()

set(FALCON_SEC_LEVELS "512" "1024") 
if(NOT FALCON_SEC_LEVEL IN_LIST FALCON_SEC_LEVELS)
    message(FATAL_ERROR "FALCON_SEC_LEVEL is not correctly defined! Should be one of ${FALCON_SEC_LEVELS}")
endif()

#[[ 
    DILITHIUM Settings
]]
set(DILITHIUM_BUILD_TYPE "avx2") 

set(DILITHIUM_BUILD_TYPES "ref" "avx2") 
if(NOT DILITHIUM_BUILD_TYPE IN_LIST DILITHIUM_BUILD_TYPES)
    message(FATAL_ERROR "DILITHIUM_BUILD_TYPE is not correctly defined! Should be one of ${DILITHIUM_BUILD_TYPES}")
endif()

set(DILITHIUM_SEC_LEVELS "2" "3" "5") 
if(NOT DILITHIUM_SEC_LEVEL IN_LIST DILITHIUM_SEC_LEVELS)
    message(FATAL_ERROR "DILITHIUM_SEC_LEVEL is not correctly defined! Should be one of ${DILITHIUM_SEC_LEVELS}")
endif()

#[[ 
    SPHINCS Settings
]]
set(SPHINCS_BUILD_TYPE "opt") 
set(SPHINCS_HASH "sha256") 
set(SPHINCS_BALANCE "s") 
set(SPHINCS_VARIANT "robust") 

set(SPHINCS_BUILD_TYPES "ref" "opt") 
if(NOT SPHINCS_BUILD_TYPE IN_LIST SPHINCS_BUILD_TYPES)
    message(FATAL_ERROR "SPHINCS_BUILD_TYPE is not correctly defined! Should be one of ${SPHINCS_BUILD_TYPES}")
endif()

set(SPHINCS_SEC_LEVELS "128" "192" "256") 
if(NOT SPHINCS_SEC_LEVEL IN_LIST SPHINCS_SEC_LEVELS)
    message(FATAL_ERROR "SPHINCS_SEC_LEVEL is not correctly defined! Should be one of ${SPHINCS_SEC_LEVELS}")
endif()

set(SPHINCS_BALANCES "f" "s") 
if(NOT SPHINCS_BALANCE IN_LIST SPHINCS_BALANCES)
    message(FATAL_ERROR "SPHINCS_BALANCE is not correctly defined! Should be one of ${SPHINCS_BALANCES}")
endif()

set(SPHINCS_HASHES "sha256" "haraka") 
if(NOT SPHINCS_HASH IN_LIST SPHINCS_HASHES)
    message(FATAL_ERROR "SPHINCS_HASH is not correctly defined! Should be one of ${SPHINCS_HASHES}")
endif()

set(SPHINCS_VARIANTS "simple" "robust") 
if(NOT SPHINCS_VARIANT IN_LIST SPHINCS_VARIANTS)
    message(FATAL_ERROR "SPHINCS_VARIANT is not correctly defined! Should be one of ${SPHINCS_VARIANTS}")
endif()

#[[ 
    HAWK Settings
]]
set(HAWK_BUILD_TYPE "opt") 

set(HAWK_BUILD_TYPES "ref" "opt") 
if(NOT HAWK_BUILD_TYPE IN_LIST HAWK_BUILD_TYPES)
    message(FATAL_ERROR "HAWK_BUILD_TYPE is not correctly defined! Should be one of ${HAWK_BUILD_TYPES}")
endif()

set(HAWK_SEC_LEVELS "512" "1024") 
if(NOT HAWK_SEC_LEVEL IN_LIST HAWK_SEC_LEVELS)
    message(FATAL_ERROR "HAWK_SEC_LEVEL is not correctly defined! Should be one of ${HAWK_SEC_LEVELS}")
endif()


#[[ 
    FAEST Settings
]]
set(FAEST_BALANCE "s") 

add_subdirectory(sqisign)
add_subdirectory(hawk)
add_subdirectory(sphincs)
add_subdirectory(dilithium)
add_subdirectory(falcon)
add_subdirectory(mqom)
add_subdirectory(ryde)
add_subdirectory(mirath)
add_subdirectory(perk)
add_subdirectory(less)
add_subdirectory(cross)
add_subdirectory(snova)
add_subdirectory(mayo)
add_subdirectory(qruov)
add_subdirectory(uov)
add_subdirectory(sdith)
add_subdirectory(faest)

