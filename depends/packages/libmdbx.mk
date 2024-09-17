package=libmdbx
$(package)_version=0.13.1
$(package)_download_path=https://libmdbx.dqdkfa.ru/release
$(package)_file_name=libmdbx-amalgamated-0.13.1.tar.xz
$(package)_sha256_hash=aabb6bf34b8699b06de717a8facf8820a2fdd1bbe4ae0e90c9a2bbdb3880181d

define $(package)_extract_cmds
    mkdir -p $($(package)_extract_dir) && \
    echo "$($(package)_sha256_hash)  $($(package)_source)" > $($(package)_extract_dir)/.$($(package)_file_name).hash && \
     $(build_SHA256SUM) -c $($(package)_extract_dir)/.$($(package)_file_name).hash && \
    $(build_TAR) --no-same-owner -xf $($(package)_source)
endef

define $(package)_config_cmds
  $($(package)_cmake) -S . -B .
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  cmake --install . --prefix $($(package)_staging_prefix_dir)
endef
