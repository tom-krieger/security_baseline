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
#   class security_baseline::rules::debian::sec_pam_passwd_sha512 {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::debian::sec_pam_passwd_sha512 (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {

  if($enforce) {
    if($facts['operatingsystem'] == 'Ubuntu') {
      $data = {
        ensure    => present,
        service   => 'common-password',
        type      => 'password',
        control   => '[success=1, default=ignore]',
        module    => 'pam_unix.so',
        arguments => ['obscure', 'use_authtok', 'try_first_pass', 'sha512'],
      }
    } else {
      $data = {
        ensure    => present,
        service   => 'common-password',
        type      => 'password',
        control   => '[success=1, default=ignore]',
        module    => 'pam_unix.so',
        arguments => ['sha512'],
        }
    }
    pam { 'pam-common-sha512':
      * => $data,
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
