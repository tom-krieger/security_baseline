# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include security_baseline::sticky_world_writabe_cron
class security_baseline::sticky_world_writabe_cron (
  Array $dirs_to_exclude = [],
) {
  $filename = '/root/world-writable-files.txt'

  file { '/usr/share/security_baseline/bin/sticy-world-writable.sh':
    ensure  => present,
    content => epp('security_baseline/sticky-world-writeable.epp', {
      filename        => $filename,
      dirs_to_exclude => $dirs_to_exclude
    }),
    owner   => 'root',
    group   => 'root',
    mode    => '0700',
  }

  file { '/etc/cron.d/sticky-world-writebale.cron':
    ensure => present,
    source => 'puppet:///modules/security_baseline/sticky-world-writeable.cron',
    owner  => 'root',
    group  => 'root',
    mode   => '0644',
  }
}
