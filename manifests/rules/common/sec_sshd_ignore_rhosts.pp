# @summary 
#    Ensure SSH IgnoreRhosts is enabled (Scored)
#
# The IgnoreRhosts parameter specifies that .rhosts and .shosts files will not be used in RhostsRSAAuthentication 
# or HostbasedAuthentication .
#
# Rationale:
# Setting this parameter forces users to enter a password when authenticating with ssh.
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
#   class security_baseline::rules::common::sec_sshd_ignore_rhosts {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_sshd_ignore_rhosts (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($facts['security_baseline']['sshd']['package']) {
    if($enforce) {
      file_line { 'ssh-ignore-rhosts':
        ensure => present,
        path   => '/etc/ssh/sshd_config',
        line   => 'IgnoreRhosts yes',
        match  => '^IgnoreRhosts.*',
        notify => Exec['reload-sshd'],
      }
    } else {
      if($facts['security_baseline']['sshd']['ignorerhosts'] != 'yes') {
        echo { 'sshd-ignore-rhosts':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
    }
  }
}
