# @summary 
#    Ensure only approved MAC algorithms are used (Scored)
#
# This variable limits the types of MAC algorithms that SSH can use during communication.
#
# Rationale:
# MD5 and 96-bit MAC algorithms are considered weak and have been shown to increase exploitability in SSH downgrade attacks. 
# Weak algorithms continue to have a great deal of attention as a weak spot that can be exploited with expanded computing 
# power. An attacker that breaks the algorithm could take advantage of a MiTM position to decrypt the SSH tunnel and capture 
# credentials and information.
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
#   class security_baseline::rules::sec_sshd_macs {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_sshd_macs (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($facts['security_baseline']['sshd']['package']) {
    if($enforce) {
      file_line { 'ssh-macs':
        ensure => present,
        path   => '/etc/ssh/sshd_config',
        line   => 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com',  #lint:ignore:140chars
        match  => '^MACs.*',
        notify => Exec['reload-sshd'],
      }
    } else {
      unless(
        ('hmac-sha2-512-etm@openssh.com' in $facts['security_baseline']['sshd']['macs']) and
        ('hmac-sha2-256-etm@openssh.com' in $facts['security_baseline']['sshd']['macs']) and
        ('umac-128-etm@openssh.com' in $facts['security_baseline']['sshd']['macs']) and
        ('hmac-sha2-512,hmac-sha2-256' in $facts['security_baseline']['sshd']['macs']) and
        ('umac-128@openssh.com' in $facts['security_baseline']['sshd']['macs'])
      ) {
        echo { 'sshd-macs':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
    }
  }
}
