# @summary 
#    Ensure system-wide crypto policy is not legacy (Scored)
#
# The system-wide crypto-policies followed by the crypto core components allow consistently deprecating 
# and disabling algorithms system-wide.
#
# The individual policy levels (DEFAULT, LEGACY, FUTURE, and FIPS) are included in the crypto-policies(7) package.
#
# Rationale:
# If the Legacy system-wide crypto policy is selected, it includes support for TLS 1.0, TLS 1.1, and SSH2 protocols 
# or later. The algorithms DSA, 3DES, and RC4 are allowed, while RSA and Diffie-Hellman parameters are accepted if 
# larger than 1023-bits.
# These legacy protocols and algorithms can make the system vulnerable to attacks, including those listed in RFC 7457.
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
#   class security_baseline::rules::redhat::sec_crypto_policy_legacy {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_crypto_policy_legacy (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($facts['security_baseline']['crypto_policy']['legacy'] != 'none') {
    echo { 'crypto-policy-legacy':
      message  => $message,
      loglevel => $log_level,
      withpath => false,
    }
  }
}
