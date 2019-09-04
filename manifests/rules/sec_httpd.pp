# @summary 
#    Ensure HTTP server is not enabled (Scored)
#
# HTTP or web servers provide the ability to host web site content.
#
# Rationale:
# Unless there is a need to run the system as a web server, it is recommended that the service be 
# disabled to reduce the potential attack surface.
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
#   class security_baseline::rules::sec_httpd {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_httpd (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    service {'httpd':
      ensure => 'stopped',
      enable => false
      }

  } else {

    if($::srv_httpd == 'enabled') {
      echo { 'httpd':
        message   => $message,
        log_level => $log_level,
        withpath  => false,
      }
    }
  }
}
