# @summary 
#    Ensure gpgcheck is globally activated (Scored)
#
# The gpgcheck option, found in the main section of the /etc/yum.conf and individual /etc/yum/repos.d/* 
# files determines if an RPM package's signature is checked prior to its installation.
#
# Rationale:
# It is important to ensure that an RPM's package signature is always checked prior to installation to 
# ensure that the software is obtained from a trusted source.
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
#   class security_baseline::rules::redhat::sec_yum_gpgcheck {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_yum_gpgcheck (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {

    file_line { 'yum_gpgcheck':
      ensure => present,
      path   => '/etc/yum.conf',
      line   => 'gpgcheck=1',
      match  => '^gpgcheck',
    }

  } else {

    if( $facts['security_baseline']['yum']['gpgcheck'] == false) {
      echo { 'yum_gpgcheck':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
