# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include security_baseline::world_writeable_files_cron
class security_baseline::world_writeable_files_cron (
  Array $dirs_to_exclude = [],
) {
  $filename = '/root/world-writable-files.txt'

  file { '/usr/share/security_baseline/bin/world-writable-files.sh':
    ensure  => present,
    content => epp('security_baseline/world-writeable-files.epp', {
      filename        => $filename,
      dirs_to_exclude => $dirs_to_exclude
    }),
    owner   => 'root',
    group   => 'root',
    mode    => '0700',
  }

  $min = fqdn_rand(60, 'sjdhgfuwdqfbqwjkc wwequ')

  file { '/etc/cron.d/world-writebale-files.cron':
    ensure  => present,
    content => epp('security_baseline/world-writeable-files.cron.epp', {min => $min}),
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
  }
}
