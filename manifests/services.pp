# @summary 
#    Additional services
#
# Services e. g. reload sshd
#
# @example
#   include security_baseline::services
class security_baseline::services {
  exec { 'reload-sshd':
    command     => 'systemctl reload sshd',
    path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
    refreshonly => true,
  }
}
