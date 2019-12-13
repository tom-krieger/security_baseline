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

  exec { 'reload-rsyslog':
    command     => 'pkill -HUP rsyslog',
    path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
    refreshonly => true,
  }

  exec { 'reload-rsyslogd':
    command     => 'pkill -HUP rsyslogd',
    path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
    refreshonly => true,
  }

  exec { 'reload-syslog-ng':
    command     => 'pkill -HUP syslog-ng',
    path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
    refreshonly => true,
  }
}
