# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include security_baseline::system_file_permissions_cron
class security_baseline::system_file_permissions_cron {
  $filename = '/usr/share/security_baseline/data/system-file-permissions.txt'

  if($facts['osfamily'] == 'RedHat') or ($facts['osfamily'] == 'Suse') {
    $cmd = 'rpm -Va --nomtime --nosize --nomd5 --nolinkto'
  } else {
    $cmd = 'dpkg --verify'
  }

  file { '/usr/share/security_baseline/bin/system-file-permissions.sh':
    ensure  => present,
    owner   => 'root',
    group   => 'root',
    mode    => '0700',
    content => epp('security_baseline/system-file-permissions-cron.epp', {cmd => $cmd, filename => $filename})
  }

  $min = fqdn_rand(60, 'msjhbcfsadzkfbzgbzghbqeghbqe w')

  file { '/etc/cron.d/system-file-permissions.cron':
    ensure  => present,
    content => epp('security_baseline/system-file-permissions.cron.epp', {min => $min}),
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
  }
}
