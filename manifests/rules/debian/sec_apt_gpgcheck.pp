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
#   class security_baseline::rules::debian::sec_apt_gpgcheck {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::debian::sec_apt_gpgcheck (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if( $facts['security_baseline']['apt']['gpgcheck'] == false) {
    echo { 'apt_gpgcheck':
      message  => $message,
      loglevel => $log_level,
      withpath => false,
    }
  }
}
