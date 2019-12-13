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
#   class security_baseline::rules::debian::sec_rsh {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::debian::sec_rsh (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {
    if(has_key($facts['security_baseline']['inetd_services'], 'srv_rsh')) {
      if($facts['security_baseline']['inetd_services']['srv_rsh']['status']) {
        file_line { 'rsh_disable':
          line     => 'disable     = yes',
          path     => $facts['security_baseline']['inetd_services']['srv_rsh']['filename'],
          match    => 'disable.*=',
          multiple => true,
        }
      }
    }
    if(has_key($facts['security_baseline']['inetd_services'], 'srv_rlogin')) {
      if($facts['security_baseline']['inetd_services']['srv_rlogin']['status']) {
        file_line { 'rlogin_disable':
          line     => 'disable     = yes',
          path     => $facts['security_baseline']['inetd_services']['srv_rlogin']['filename'],
          match    => 'disable.*=',
          multiple => true,
        }
      }
    }
    if(has_key($facts['security_baseline']['inetd_services'], 'srv_rexec')) {
      if($facts['security_baseline']['inetd_services']['srv_rexec']['status']) {
        file_line { 'rexec_disable':
          line     => 'disable     = yes',
          path     => $facts['security_baseline']['inetd_services']['srv_rexec']['filename'],
          match    => 'disable.*=',
          multiple => true,
        }
      }
    }
  } else {
    if (
      (has_key($facts['security_baseline']['inetd_services'], 'srv_rsh') and
      ($facts['security_baseline']['inetd_services']['srv_rsh']['status']))        or
      (has_key($facts['security_baseline']['inetd_services'], 'srv_rlogin') and
      ($facts['security_baseline']['inetd_services']['srv_rlogin']['status']))     or
      (has_key($facts['security_baseline']['inetd_services'], 'srv_rexec') and
      ($facts['security_baseline']['inetd_services']['srv_rexec']['status']))
    ) {
      echo { 'rsh-service':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
