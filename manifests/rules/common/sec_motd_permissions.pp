# @summary A short summary of the purpose of this class
#
# A description of what this class does
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
#   class security_baseline::rules::common::sec_motd_permissions {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_motd_permissions (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    unless(defined(File['/etc/motd'])) {
      file { '/etc/motd':
        ensure => present,
        owner  => 'root',
        group  => 'root',
        mode   => '0644',
      }
    }

  } else {
    if($facts['security_baseline']['motd']['combined'] != '0-0-420') {
      echo { 'motd-perms':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
