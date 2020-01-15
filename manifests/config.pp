# @summary 
#    Configuration stuff
#
# Run configuration stuff
#
# @param update_postrun_command
#    Update the post run command of Puppet agent
#
# @param fact_upload_command
#    Command to use to upload facts to Puppet master
#
# @param reporting_type
#    Selects the report type to be written
#
# @example
#   include security_baseline::config
class security_baseline::config(
  Boolean $update_postrun_command          = true,
  String $fact_upload_command              = '/usr/local/bin/puppet facts upload',
  Enum['fact', 'csv_file'] $reporting_type = 'fact',
) {
  file { '/usr/share/security_baseline':
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }
  file { '/usr/share/security_baseline/logs':
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }
  file { '/usr/share/security_baseline/data':
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }
  file { '/usr/share/security_baseline/bin':
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }

  if ($facts['operatingsystem'] == 'Ubuntu') {
    file { '/usr/share/security_baseline/bin/check_dot_files_write.sh':
      ensure => present,
      source => 'puppet:///modules/security_baseline/check_dot_files_write.sh.ubuntu',
      owner  => 'root',
      group  => 'root',
      mode   => '0700',
    }

    file { '/usr/share/security_baseline/bin/check_forward_files.sh':
      ensure => present,
      source => 'puppet:///modules/security_baseline/check_forward_files.sh.ubuntu',
      owner  => 'root',
      group  => 'root',
      mode   => '0700',
    }

    file { '/usr/share/security_baseline/bin/check_home_dir_owner.sh':
      ensure => present,
      source => 'puppet:///modules/security_baseline/check_home_dir_owner.sh.ubuntu',
      owner  => 'root',
      group  => 'root',
      mode   => '0700',
    }

    file { '/usr/share/security_baseline/bin/check_home_dir_permissions.sh':
      ensure => present,
      source => 'puppet:///modules/security_baseline/check_home_dir_permissions.sh.ubuntu',
      owner  => 'root',
      group  => 'root',
      mode   => '0700',
    }

    file { '/usr/share/security_baseline/bin/check_netrc_files_write.sh':
      ensure => present,
      source => 'puppet:///modules/security_baseline/check_netrc_files_write.sh.ubuntu',
      owner  => 'root',
      group  => 'root',
      mode   => '0700',
    }

    file { '/usr/share/security_baseline/bin/check_netrc_files.sh':
      ensure => present,
      source => 'puppet:///modules/security_baseline/check_netrc_files.sh.ubuntu',
      owner  => 'root',
      group  => 'root',
      mode   => '0700',
    }

    file { '/usr/share/security_baseline/bin/check_rhosts_files.sh':
      ensure => present,
      source => 'puppet:///modules/security_baseline/check_rhosts_files.sh.ubuntu',
      owner  => 'root',
      group  => 'root',
      mode   => '0700',
    }

    file { '/usr/share/security_baseline/bin/check_user_home_dirs.sh':
      ensure => present,
      source => 'puppet:///modules/security_baseline/check_user_home_dirs.sh.ubuntu',
      owner  => 'root',
      group  => 'root',
      mode   => '0700',
    }
  } else {
    if ($facts['operatingsystem'] == 'Debian') {
      $nologin = '/usr/sbin/nologin'
    } else {
      $nologin = '/sbin/nologin'
    }

    file { '/usr/share/security_baseline/bin/check_dot_files_write.sh':
      ensure  => present,
      content => epp('security_baseline/security_baseline/check_dot_files_write.sh.epp', {nologin => $nologin}),
      owner   => 'root',
      group   => 'root',
      mode    => '0700',
    }

    file { '/usr/share/security_baseline/bin/check_forward_files.sh':
      ensure  => present,
      content => epp('security_baseline/security_baseline/check_forward_files.sh.epp', {nologin => $nologin}),
      owner   => 'root',
      group   => 'root',
      mode    => '0700',
    }

    file { '/usr/share/security_baseline/bin/check_home_dir_owner.sh':
      ensure  => present,
      content => epp('security_baseline/security_baseline/check_home_dir_owner.sh.epp', {nologin => $nologin}),
      owner   => 'root',
      group   => 'root',
      mode    => '0700',
    }
    file { '/usr/share/security_baseline/bin/check_home_dir_permissions.sh':
      ensure  => present,
      content => epp('security_baseline/security_baseline/check_home_dir_permissions.sh.epp', {nologin => $nologin}),
      owner   => 'root',
      group   => 'root',
      mode    => '0700',
    }

    file { '/usr/share/security_baseline/bin/check_netrc_files_write.sh':
      ensure  => present,
      content => epp('security_baseline/security_baseline/check_netrc_files_write.sh.epp', {nologin => $nologin}),
      owner   => 'root',
      group   => 'root',
      mode    => '0700',
    }

    file { '/usr/share/security_baseline/bin/check_netrc_files.sh':
      ensure  => present,
      content => epp('security_baseline/security_baseline/check_netrc_files.sh.epp', {nologin => $nologin}),
      owner   => 'root',
      group   => 'root',
      mode    => '0700',
    }

    file { '/usr/share/security_baseline/bin/check_rhosts_files.sh':
      ensure  => present,
      content => epp('security_baseline/security_baseline/check_rhosts_files.sh.epp', {nologin => $nologin}),
      owner   => 'root',
      group   => 'root',
      mode    => '0700',
    }

    file { '/usr/share/security_baseline/bin/check_user_home_dirs.sh':
      ensure  => present,
      content => epp('security_baseline/security_baseline/check_user_home_dirs.sh.epp', {nologin => $nologin}),
      owner   => 'root',
      group   => 'root',
      mode    => '0700',
    }
  }

  file { '/usr/share/security_baseline/bin/root_path_integrity.sh':
    ensure => present,
    source => 'puppet:///modules/security_baseline/root_path_integrity.sh',
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }

  file { '/usr/share/security_baseline/bin/check_passwd_group_exist.sh':
    ensure => present,
    source => 'puppet:///modules/security_baseline/check_passwd_group_exist.sh',
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }

  file { '/usr/share/security_baseline/bin/update_pam_pw_requirements_config.sh':
    ensure => present,
    source => 'puppet:///modules/security_baseline/update_pam_pw_requirements_config.sh',
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }

  file { '/usr/share/security_baseline/bin/update_pam_lockout_config.sh':
    ensure => present,
    source => 'puppet:///modules/security_baseline/update_pam_lockout_config.sh',
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }

  file { '/usr/share/security_baseline/bin/update_pam_pw_reuse_config.sh':
    ensure => present,
    source => 'puppet:///modules/security_baseline/update_pam_pw_reuse_config.sh',
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }

  file { '/usr/share/security_baseline/bin/update_pam_pw_hash_sha512_config.sh':
    ensure => present,
    source => 'puppet:///modules/security_baseline/update_pam_pw_hash_sha512_config.sh',
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }

  if $update_postrun_command and ($reporting_type == 'fact') {
    if(('security_baseline' in $facts) and ('puppet_agent_postrun' in $facts['security_baseline'])) {
      if ($facts['security_baseline']['puppet_agent_postrun'] != "postrun_command = ${fact_upload_command}") {
        exec { 'set puppet agent postrun agent':
          command => "puppet config --section agent set postrun_command \"${fact_upload_command}\"",
          path    => ['/bin', '/usr/bin', '/usr/local/bin'],
        }
        exec { 'set puppet agent postrun main':
          command => "puppet config --section main set postrun_command \"${fact_upload_command}\"",
          path    => ['/bin', '/usr/bin', '/usr/local/bin'],
        }
      }
    }
  }
}
