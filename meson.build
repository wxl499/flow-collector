project('dpdk_flow_collector', 'c',
  version : '0.1',
  default_options : ['warning_level=3'])

dpdk = dependency('libdpdk')

executable('dpdk_flow_collector',
  'dpdk_flow_collector.c',
  dependencies : [dpdk],
  install : true)