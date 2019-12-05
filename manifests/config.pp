# @summary 
#    Configuration stuff
#
# Run configuration stuff
#
# @example
#   include security_baseline::config
class security_baseline::config {
  file { '/usr/local/security_baseline_scripts':
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }

  file { '/usr/local/security_baseline_scripts/root_path_integrity.sh':
    ensure => present,
    source => 'puppet:///modules/security_baseline/root_path_integrity.sh',
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }

  file { '/usr/local/security_baseline_scripts/check_user_home_dirs.sh':
    ensure => present,
    source => 'puppet:///modules/security_baseline/check_user_home_dirs.sh',
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }

  file { '/usr/local/security_baseline_scripts/check_home_dir_permissions.sh':
    ensure => present,
    source => 'puppet:///modules/security_baseline/check_home_dir_permissions.sh',
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }

  file { '/usr/local/security_baseline_scripts/check_home_dir_owner.sh':
    ensure => present,
    source => 'puppet:///modules/security_baseline/check_home_dir_owner.sh',
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }

  file { '/usr/local/security_baseline_scripts/ss_write.sh':
    ensure => present,
    source => 'puppet:///modules/security_baseline/check_dot_files_write.sh',
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }

  file { '/usr/local/security_baseline_scripts/check_forward_files.sh':
    ensure => present,
    source => 'puppet:///modules/security_baseline/check_forward_files.sh',
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }

  file { '/usr/local/security_baseline_scripts/check_netrc_files.sh':
    ensure => present,
    source => 'puppet:///modules/security_baseline/check_netrc_files.sh',
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }

  file { '/usr/local/security_baseline_scripts/check_netrc_files_write.sh':
    ensure => present,
    source => 'puppet:///modules/security_baseline/check_netrc_files_write.sh',
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }

  file { '/usr/local/security_baseline_scripts/check_rhosts_files.sh':
    ensure => present,
    source => 'puppet:///modules/security_baseline/check_rhosts_files.sh',
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }

  file { '/usr/local/security_baseline_scripts/check_passwd_group_exist.sh':
    ensure => present,
    source => 'puppet:///modules/security_baseline/check_passwd_group_exist.sh',
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }

  if(('security_baseline' in $facts) and ('puppet_agent_postrun' in $facts['security_baseline'])) {
    if ($facts['security_baseline']['puppet_agent_postrun'] != 'postrun_command = /usr/local/bin/puppet facts upload') {
      exec { 'set puppet agent postrun agent':
        command => 'puppet config --section agent set postrun_command "/usr/local/bin/puppet facts upload"',
        path    => ['/bin', '/usr/bin', '/usr/local/bin'],
      }
      exec { 'set puppet agent postrun main':
        command => 'puppet config --section main set postrun_command "/usr/local/bin/puppet facts upload"',
        path    => ['/bin', '/usr/bin', '/usr/local/bin'],
      }
    }
  } else {
    exec { 'set puppet agent postrun agent':
      command => 'puppet config --section agent set postrun_command "/usr/local/bin/puppet facts upload"',
      path    => ['/bin', '/usr/bin', '/usr/local/bin'],
    }
    exec { 'set puppet agent postrun main':
      command => 'puppet config --section main set postrun_command "/usr/local/bin/puppet facts upload"',
      path    => ['/bin', '/usr/bin', '/usr/local/bin'],
    }
  }
}
