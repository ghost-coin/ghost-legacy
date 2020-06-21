package=hidapi
$(package)_version=0.9.0-rc1
$(package)_download_path=https://github.com/libusb/hidapi/archive
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=6501f90747ed66d22d8fd246a4dd6769801b2360c18d785e07725a05569c3f12
$(package)_linux_dependencies=libusb

define $(package)_set_vars
  $(package)_config_opts=--disable-shared
  $(package)_config_opts_linux=--with-pic
endef

define $(package)_preprocess_cmds
  sed -i '64,67d' configure.ac; \
  sed -i '64iLIBS_HIDRAW_PR+=" -ludev"' configure.ac; \
  cd $($(package)_build_subdir); ./bootstrap
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef