if get_option('gusb')
cargs = ['-DG_LOG_DOMAIN="FuPluginlenovodock"']

install_data(['lenovo-dock.quirk'],
  install_dir: join_paths(datadir, 'fwupd', 'quirks.d')
)

shared_module('fu_plugin_lenovo_dock',
  fu_hash,
  sources : [
    'fu-plugin-lenovo-dock.c',
    'fu-lenovo-dock-device.c',
    'fu-lenovo-dock-firmware.c',
  ],
  include_directories : [
    root_incdir,
    fwupd_incdir,
    fwupdplugin_incdir,
  ],
  install : true,
  install_dir: plugin_dir,
  link_with : [
    fwupd,
    fwupdplugin,
  ],
  c_args : cargs,
  dependencies : [
    plugin_deps,
  ],
)
endif
