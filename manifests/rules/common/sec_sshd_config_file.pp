# @summary 
#    Ensure permissions on /etc/ssh/sshd_config are configured (Scored)
#
# The /etc/ssh/sshd_config file contains configuration specifications for sshd. The command below sets 
# the owner and group of the file to root.
#
# Rationale:
# The /etc/ssh/sshd_config file needs to be protected from unauthorized changes by non-privileged users.
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
#   class security_baseline::rules::common::sec_sshd_config_file {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_sshd_config_file (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($facts['security_baseline']['sshd']['package']) {
    if($enforce) {
      file { '/etc/ssh/sshd_config':
        ensure => file,
        owner  => 'root',
        group  => 'root',
        mode   => '0600',
      }
    } else {
      if(
        ($facts['security_baseline']['sshd']['/etc/ssh/sshd_config']['uid'] != 0) or
        ($facts['security_baseline']['sshd']['/etc/ssh/sshd_config']['gid'] != 0) or
        ($facts['security_baseline']['sshd']['/etc/ssh/sshd_config']['mode'] != 384)
      ) {
        echo { 'sshd-config-file':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
    }
  }
}
