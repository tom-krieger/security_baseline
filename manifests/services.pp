# @summary 
#    Additional services
#
# Services e. g. reload sshd
#
# @example
#   include security_baseline::services
class security_baseline::services {
  exec { 'reload-sshd':
    command     => 'systemctl reloadf sshd',
    path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
    refreshonly => true,
  }
}
