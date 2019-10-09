# @summary 
#    Ensure password hashing algorithm is SHA-512 (Scored)
#
# The commands below change password encryption from md5 to sha512 (a much stronger hashing algorithm). All 
# existing accounts will need to perform a password change to upgrade the stored hashes to the new algorithm.
#
# Rationale:
# The SHA-512 algorithm provides much stronger hashing than MD5, thus providing additional protection to the system by 
# increasing the level of effort for an attacker to successfully determine passwords.
#
# Note that these change only apply to accounts configured on the local system.
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
#   class security_baseline::rules::sec_pam_passwd_sha512 {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_pam_passwd_sha512 (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  $services = [
    'system-auth',
    'password-auth',
  ]

  if($enforce) {

    $services.each | $service | {

      pam { "pam-${service}-sha512":
        ensure    => positioned,
        service   => $service,
        type      => 'password',
        control   => 'sufficient',
        module    => 'pam_unix.so',
        arguments => ['sha512'],
        position  => 'after *[type="password" and module="pam_unix.so" and control="requisite"]',
      }

    }
  } else {
    unless ($facts['security_baseline']['pam']['sha512']['status']) {
      echo { 'password-sha512':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
