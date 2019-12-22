# @summary 
#    Ensure system-wide crypto policy is not over-ridden (Scored)
#
# System-wide Crypto policy can be over-ridden or opted out of for openSSH.
#
# Rationale:
# Over-riding or opting out of the system-wide crypto policy could allow for the use of 
# less secure Ciphers, MACs, KexAlgoritms and GSSAPIKexAlgorithsm.
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
#   class security_baseline::rules::common::sec_sshd_crypto_policy {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_sshd_crypto_policy (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if ($enforce) {
    file_line { 'sshd-crypto-policy':
      ensure            => absent,
      path              => '/etc/ssh/sshd_config',
      match             => '^\s*CRYPTO_POLICY\s*=.*',
      match_for_absence => true,
      notify            => Exec['reload-sshd'],
    }
  } else {
    if($facts['security_baseline']['sshd']['maxstartups'] != 'yes') {
        echo { 'sshd-crypto-policy':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
  }
}
