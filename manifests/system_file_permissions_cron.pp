# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include security_baseline::system_file_permissions_cron
class security_baseline::system_file_permissions_cron {
  $filename = '/root/system-file-permissions.txt'

  file { '/usr/local/sbin/system-file-permissions.sh':
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0700',
    content => epp('security_baseline/system-file-permissions-cron.epp', {filename => $filename})
  }

  file { '/etc/cron.d/system-file-permissions.cron':
    ensure => file,
    source => 'puppet:///modules/security_baseline/system-file-permissions.cron',
    owner  => 'root',
    group  => 'root',
    mode   => '0644',
  }
}
