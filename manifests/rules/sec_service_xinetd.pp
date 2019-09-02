# @summary 
#    Ensure xinetd is not enabled (Scored)
#
#  The eXtended InterNET Daemon ( xinetd ) is an open source super daemon that replaced the 
# original inetd daemon. The xinetd daemon listens for well known services and dispatches the 
# appropriate daemon to properly respond to service requests.
#
# Rationale:
# If there are no xinetd services required, it is recommended that the daemon be disabled.
#
# @param enforce
#    Enforce the rule or just test and log
#
# @param message
#    Message to print into the log
#
# @param loglevel
#    The loglevel for the above message
#
# @example
#   class security_baseline::rules::sec_service_xinetd {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_service_xinetd (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    service { 'xinetd':
      ensure => stopped,
      enable => false,
    }

  } else {

    if($::srv_xinetd == true) {

      echo { 'xin etd-service':
        message  => $message,
        loglevel => $loglevel,
        withpath => false,
      }

    }
  }
}
