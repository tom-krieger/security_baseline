# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include security_baseline::rules::debian::sec_service_openbsd_inetd
class security_baseline::rules::debian::sec_service_openbsd_inetd (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    if!(defined(Package['openbsd-inetd'])) {
      package { 'openbsd-inetd':
        ensure => absent,
      }
    }
  } else {
    if($facts['security_baseline']['packages_installed']['openbsd-inetd']) {
      echo { 'openbsd-inetd':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
