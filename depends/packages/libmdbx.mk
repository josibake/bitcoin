package=libmdbx
$(package)_version=0.12.11
$(package)_download_path=https://libmdbx.dqdkfa.ru/release
$(package)_file_name=$(package)-amalgamated-$($(package)_version).tar.xz
$(package)_sha256_hash=427184bc8b04e13939e466e1e752e00c52e6aa080e62daf8d0536c36d9412b2b

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
