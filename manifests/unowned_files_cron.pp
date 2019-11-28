# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include security_baseline::unowned_files_cron
class security_baseline::unowned_files_cron {
  $unowned_user = '/root/unowned_files_user.txt'
  $unowned_group = '/root/unowned_files_group.txt'

  file { '/usr/local/sbin/unowned_files.sh':
    ensure  => file,
    content => epp('security_baseline/unowned-files.epp', {
      unowned_user  => $unowned_user,
      unowned_group => $unowned_group,
    }),
    owner   => 'root',
    group   => 'root',
    mode    => '0700',
  }

  file { '/etc/cron.d/unowned-files.cron':
    ensure => file,
    source => 'puppet:///modules/security_baseline/unowned-files.cron',
    owner  => 'root',
    group  => 'root',
    mode   => '0644',
  }
}
