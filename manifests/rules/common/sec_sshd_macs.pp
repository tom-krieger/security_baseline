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
# @param macs
#    MAC algorithms to add to config
#
# @example
#   class security_baseline::rules::common::sec_sshd_macs {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_sshd_macs (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
  Array $macs       = [],
) {
  if($facts['security_baseline']['sshd']['package']) {
    if($enforce) {
      if (!empty($macs)) {
        $maclist = $macs.join(',')
        file_line { 'sshd-macs':
          ensure => present,
          path   => '/etc/ssh/sshd_config',
          line   => "MACs ${maclist}",
          match  => '^MACs.*',
          notify => Exec['reload-sshd'],
        }
      }
    } else {
      $macs.each |$mac| {
        if(!($mac in $facts['security_baseline']['sshd']['macs'])) {
          echo { "sshd-macs-${mac}":
            message  => "${message} (${mac})",
            loglevel => $log_level,
            withpath => false,
          }
        }
      }
    }
  }
}
