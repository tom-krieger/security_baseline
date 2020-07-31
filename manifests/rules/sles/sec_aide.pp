# @summary 
#    Ensure AIDE is installed (Scored)
#
# AIDE takes a snapshot of filesystem state including modification times, permissions, and file hashes 
# which can then be used to compare against the current state of the filesystem to detect modifications 
# to the system.
#
# Rationale:
# By monitoring the filesystem state compromised files can be detected to prevent or limit the exposure 
# of accidental or malicious misconfigurations or modified binaries.
#
# @param enforce
#    Enforce the rule or just test and log
#
# @param message
#    Message to print into the log
#
# @param log_level
#    The log_level for the above message
#
# @example
#   class security_baseline::rules::sles::sec_aide {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sles::sec_aide (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {

  if($enforce) {

    ensure_packages(['aide'], {
      ensure => installed,
      notify => Exec['aidedb'],
    })

    exec { 'aidedb':
      command     => 'aide --init',
      path        => '/sbin/',
      refreshonly => true,
      notify      => Exec['rename_aidedb'],
      require     => Package['aide'],
    }

    exec { 'rename_aidedb':
      command     => 'mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz',
      creates     => '/var/lib/aide/aide.db.gz',
      path        => '/bin/:/sbin/:/usr/bin/:/usr/sbin/',
      logoutput   => true,
      refreshonly => true,
      require     => Package['aide'],
    }

  } else {

    if(
      ($facts['security_baseline']['aide']['version'] == 'none') or
      ($facts['security_baseline']['aide']['status'] == 'not installed')
    ) {
      echo { 'aide':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
