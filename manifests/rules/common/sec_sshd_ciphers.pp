# @summary 
#    Ensure only strong Ciphers are used (Scored)
#
# This variable limits the ciphers that SSH can use during communication.
#
# Rationale:
# Weak ciphers that are used for authentication to the cryptographic module cannot be relied upon to provide 
# confidentiality or integrity, and system data may be compromised.
#
# The DES, Triple DES, and Blowfish ciphers, as used in SSH, have a birthday bound of approximately four billion blocks, 
# which makes it easier for remote attackers to obtain cleartext data via a birthday attack against a long-duration 
# encrypted session, aka a "Sweet32" attack.
#
# The RC4 algorithm, as used in the TLS protocol and SSL protocol, does not properly combine state data with key data 
# during the initialization phase, which makes it easier for remote attackers to conduct plaintext-recovery attacks 
# against the initial bytes of a stream by sniffing network traffic that occasionally relies on keys affected by the 
# Invariance Weakness, and then using a brute-force approach involving LSB values, aka the "Bar Mitzvah" issue.
#
# The passwords used during an SSH session encrypted with RC4 can be recovered by an attacker who is able to capture and 
# replay the session.
#
# Error handling in the SSH protocol; Client and Server, when using a block cipher algorithm in Cipher Block Chaining (CBC) 
# mode, makes it easier for remote attackers to recover certain plaintext data from an arbitrary block of ciphertext in an 
# SSH session via unknown vectors.
#
# The mm_newkeys_from_blob function in monitor_wrap.c, when an AES-GCM cipher is used, does not properly initialize memory 
# for a MAC context data structure, which allows remote authenticated users to bypass intended ForceCommand and login-shell 
# restrictions via packet data that provides a crafted callback address.
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
# @param ciphers
#    Ciphers to add to config
#
# @example
#   class security_baseline::rules::common::sec_sshd_ciphers {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_sshd_ciphers (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
  Array $ciphers    = [],
) {
  if($facts['security_baseline']['sshd']['package']) {
    if($enforce) {
      if (!empty($ciphers)) {
        $cipherlist = $ciphers.join(',')
        file_line { 'sshd-ciphers':
          ensure => present,
          path   => '/etc/ssh/sshd_config',
          line   => "Ciphers ${cipherlist}",
          match  => '^Ciphers.*',
          notify => Exec['reload-sshd'],
        }
      }
    } else {
      $ciphers.each |$cipher| {
        if(!($cipher in $facts['security_baseline']['sshd']['ciphers'])) {
          echo { "sshd-ciphers-${cipher}":
            message  => "${message} (${cipher})",
            loglevel => $log_level,
            withpath => false,
          }
        }
      }
    }
  }
}
