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
# This rule is done together with sec_pam_old_passwords
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
# @param sha512
#    Use sha512 password encryption (only used in Redhat 8, for 7 or less is done in sec_pam_old_passwords)
#
# @example
#   class security_baseline::rules::redhat::sec_pam_passwd_sha512 {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_pam_passwd_sha512 (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
  Boolean $sha512   = true,
) {
  $services = [
    'system-auth',
    'password-auth',
  ]

  if($enforce) {

    if($sha512) and ($facts['operatingsystemmajrelease'] > '7') {
      if (
        (has_key($facts['security_baseline'], 'authselect')) and
        ($facts['security_baseline']['authselect']['profile'] != 'none')
      ) {
        $pf_path = "/etc/authselect/custom/${facts['security_baseline']['authselect']['profile']}"

        $services.each | $service | {
          $pf_file = "${pf_path}/${service}"

          exec { "update authselect config for sha512 ${service}":
            command => "sed -ri 's/^\\s*(password\\s+sufficient\\s+pam_unix.so\\s+)(.*)$/\\1\\2 sha512/' ${pf_file}",
            path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            onlyif  => "test -z \"\$(grep -E '^\\s*password\\s+sufficient\\s+pam_unix.so\\s+.*sha512\\s*.*\$' ${pf_file})\"",
            notify  => Exec['authselect-apply-changes'],
          }
        }
      } else {
        echo { 'no custom authselect profile sha512':
          message  => 'no custom authselect profile available, postpone configuration',
          loglevel => $log_level,
          withpath => false,
        }
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
