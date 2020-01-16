# @summary #    Ensure only strong Key Exchange algorithms are used (Scored)
#
# Key exchange is any method in cryptography by which cryptographic keys are exchanged between two parties, allowing 
# use of a cryptographic algorithm. If the sender and receiver wish to exchange encrypted messages, each must be 
# equipped to encrypt messages to be sent and decrypt messages received
#
# Rationale:
# Key exchange methods that are considered weak should be removed. A key exchange method may be weak because too few 
# bits are used, or the hashing algorithm is considered too weak. Using weak algorithms could expose connections to 
# man-in-the-middle attacks.
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
# @param kexs
#    Key exchange methods to add to config
#
# @example
#   class security_baseline::rules::common::sec_sshd_kex {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_sshd_kex (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
  Array $kexs       = [],
) {
  if($facts['security_baseline']['sshd']['package']) {
    if($enforce) {
      if (!empty($kexs)) {
        $kexlist = $kexs.join(',')
        file_line { 'sshd-kexs':
          ensure => present,
          path   => '/etc/ssh/sshd_config',
          line   => "Kexalgorithms ${kexlist}",
          match  => '^Kexalgorithms.*',
          notify => Exec['reload-sshd'],
        }
      }
    } else {
      $kexs.each |$kex| {
        if(!($kex in $facts['security_baseline']['sshd']['kexalgorithms'])) {
          echo { "sshd-kexs-${kex}":
            message  => "${message} (${kex})",
            loglevel => $log_level,
            withpath => false,
          }
        }
      }
    }
  }
}
