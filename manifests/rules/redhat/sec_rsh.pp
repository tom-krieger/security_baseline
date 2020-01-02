# @summary 
#    Ensure rsh server is not enabled (Scored)
#
# The Berkeley rsh-server ( rsh , rlogin , rexec ) package contains legacy services that exchange credentials 
# in clear-text.
#
# Rationale:
# These legacy services contain numerous security exposures and have been replaced with the more secure SSH package.
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
#   class security_baseline::rules::redhat::sec_rsh {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_rsh (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {
    if($facts['operatingsystemmajrelease'] > '6') {
      $srvs = ['rsh.socket', 'rlogin.socket', 'rexec.socket']
    } else {
      $srvs = ['rsh', 'rlogin', 'rexec']
    }
    $srvs.each |$srv| {
      service { $srv:
        ensure => 'stopped',
        enable => false,
      }
    }

  } else {

    if($facts['security_baseline']['xinetd_services']['srv_rsh']) {
      echo { 'rsh-service':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
