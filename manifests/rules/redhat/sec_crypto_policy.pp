# @summary 
#    Ensure system-wide crypto policy is FUTURE or FIPS (Scored)
#
# The system-wide crypto-policies followed by the crypto core components allow consistently deprecating 
# and disabling algorithms system-wide.
# The individual policy levels (DEFAULT, LEGACY, FUTURE, and FIPS) are included in the crypto-policies(7) 
# package.
#
# Rationale:
# If the Legacy system-wide crypto policy is selected, it includes support for TLS 1.0, TLS 1.1, and SSH2 protocols 
# or later. The algorithms DSA, 3DES, and RC4 are allowed, while RSA and Diffie-Hellman parameters are accepted if 
# larger than 1023-bits.
# 
# These legacy protocols and algorithms can make the system vulnerable to attacks, including those listed in RFC 7457.
# 
# FUTURE: Is a conservative security level that is believed to withstand any near-term future attacks. This level does 
# not allow the use of SHA-1 in signature algorithms. The RSA and Diffie-Hellman parameters are accepted if larger than 
# 3071 bits. The level provides at least 128-bit security.
#
# FIPS: Conforms to the FIPS 140-2 requirements. This policy is used internally by the fips-mode-setup(8) tool which can 
# switch the system into the FIPS 140-2 compliance mode. The level provides at least 112-bit security
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
# @param crypto_policy
#    he crypto policy to set in enforce mode.
#
# @example
#   class security_baseline::rules::redhat::sec_crypto_policy {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#       crypto_policy = 'FUTURE',
#   }
#
# @api private
class security_baseline::rules::redhat::sec_crypto_policy (
  Boolean $enforce                                = true,
  String $message                                 = '',
  String $log_level                               = '',
  Enum['FUTURE', 'FIPS', 'LEGACY'] $crypto_policy = 'FUTURE',
) {
  if ($enforce) {
    if ($facts['security_baseline']['crypto_policy']['policy'] != $crypto_policy) {
      exec { "set crypto policy to ${crypto_policy}":
        command => "update-crypto-policies --set ${crypto_policy}",
        path    => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
      }
      if($crypto_policy == 'FUTURE') {
        $enable = 'disable'
      } elsif($crypto_policy == 'FIPS') {
        $enable = 'enable'
      }
      if (
        (($enable == 'enable') and ($facts['security_baseline']['crypto_policy']['fips_mode'] == 'disabled')) or
        (($enable == 'disable') and ($facts['security_baseline']['crypto_policy']['fips_mode'] == 'enabled'))
      ) {
        exec { "set FIPS to ${enable}":
          command => "fips-mode-setup --${enable}",
          path    => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
        }
      }
    }
  } else {
    if (
      ($facts['security_baseline']['crypto_policy']['policy'] != 'FUTURE') and
      ($facts['security_baseline']['crypto_policy']['policy'] != 'FIPS')
    ) {
      echo { 'crypto-policy':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
