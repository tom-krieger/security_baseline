# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include security_baseline::services
class security_baseline::services {
  exec { 'reload-sshd':
    command     => 'pkill -HUP sshd',
    path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
    refreshonly => true,
  }
}
