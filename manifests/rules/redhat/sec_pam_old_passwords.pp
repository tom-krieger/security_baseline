# @summary 
#    Ensure password reuse is limited (Scored)
#
# The /etc/security/opasswd file stores the users' old passwords and can be checked to ensure that users 
# are not recycling recent passwords.
#
# Rationale:
# Forcing users not to reuse their past 5 passwords make it less likely that an attacker will be able to 
# guess the password.
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
# @param oldpasswords
#    Number of old passwords to remember
#
# @param sha512
#    Enable or disable sha512 password encryption
#
# @example
#   class security_baseline::rules::redhat::ssec_pam_pw_requirements {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::redhat::sec_pam_old_passwords (
  Boolean $enforce            = true,
  String $message             = '',
  String $log_level           = '',
  Integer $oldpasswords       = 5,
  Boolean $sha512             = true,
) {
  $services = [
    'system-auth',
    'password-auth',
  ]

  if($enforce) {
    if (
      (has_key($facts['security_baseline'], 'authselect')) and
      ($facts['security_baseline']['authselect']['profile'] != 'none')
    ) {
      $pf_path = "/etc/authselect/custom/${facts['security_baseline']['authselect']['profile']}"
    } else {
      $pf_path = ''
    }

    if ($facts['operatingsystemmajrelease'] > '7') {

      if $pf_path != '' {
        $pf_file = "${pf_path}/system-auth"

        exec { 'update authselect config for old passwords':
          command => "sed -ri 's/^\\s*(password\\s+(requisite|sufficient)\\s+(pam_pwquality\\.so|pam_unix\\.so)\\s+)(.*)(remember=\\S+\\s*)(.*)$/\\1\\4 remember=${oldpasswords} \\6/' ${pf_file} || sed -ri 's/^\\s*(password\\s+(requisite|sufficient)\\s+(pam_pwquality\\.so|pam_unix\\.so)\\s+)(.*)$/\\1\\4 remember=${oldpasswords}/' ${pf_file}", #lint:ignore:140chars
          path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          onlyif  => "test -z '\$(grep -E '^\\s*password\\s+(sufficient\\s+pam_unix|requi(red|site)\\s+pam_pwhistory).so\\s+ ([^#]+\\s+)*remember=\\S+\s*.*\$' ${pf_file})'", #lint:ignore:140chars
          notify  => Exec['authselect-apply-changes'],
        }
      } else {
        echo { 'old passwords: no custom authselect profile old password':
          message  => 'old passwords: no custom authselect profile available, postpone configuration',
          loglevel => $log_level,
          withpath => false,
        }
      }

    } else {

      $services.each | $service | {
        if($sha512) {
          $arguments = ["remember=${oldpasswords}", 'shadow', 'sha512', 'try_first_pass', 'use_authtok']
        } else {
          $arguments = ["remember=${oldpasswords}", 'shadow', 'try_first_pass', 'use_authtok']
        }

        Pam { "pam-${service}-sufficient":
          ensure    => present,
          service   => $service,
          type      => 'password',
          control   => 'sufficient',
          module    => 'pam_unix.so',
          arguments => $arguments,
          position  => 'after *[type="password" and module="pam_unix.so" and control="requisite"]',
        }
      }
    }
  } else {
    unless ($facts['security_baseline']['pam']['opasswd']['status']) {
      echo { 'password-reuse':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
