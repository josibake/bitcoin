# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

find_path(MDBX_INCLUDE_DIR
  NAMES mdbx.h++
)

find_library(MDBX_LIBRARY
  NAMES mdbx
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MDBX
  REQUIRED_VARS MDBX_LIBRARY MDBX_INCLUDE_DIR
)

if(MDBX_FOUND AND NOT TARGET MDBX::MDBX)
  add_library(MDBX::MDBX STATIC IMPORTED)
  set_target_properties(MDBX::MDBX PROPERTIES
    IMPORTED_LOCATION "${MDBX_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${MDBX_INCLUDE_DIR}"
  )
endif()

mark_as_advanced(
  MDBX_INCLUDE_DIR
  MDBX_LIBRARY
)
