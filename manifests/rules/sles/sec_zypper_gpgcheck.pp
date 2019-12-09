# @summary 
#    Ensure GPG keys are configured (Not Scored)
#
# Most packages managers implement GPG key signing to verify package integrity during installation.
#
# Rationale:
# It is important to ensure that updates are obtained from a valid source to protect against spoofing 
# that could lead to the inadvertent installation of malware on the system.
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
#   class security_baseline::rules::sles::sec_zypper_gpgcheck {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sles::sec_zypper_gpgcheck (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {

    file_line { 'zypper_gpgcheck':
      ensure => present,
      path   => '/etc/zypp/zypp.conf',
      line   => 'gpgcheck = on',
      match  => '^gpgcheck',
    }

  } else {

    if( $facts['security_baseline']['zypper']['gpgcheck'] == false) {
      echo { 'zypper_gpgcheck':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
