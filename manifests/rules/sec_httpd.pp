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
# @param loglevel
#    The loglevel for the above message
#
# @example
#   class security_baseline::rules::sec_httpd {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_httpd (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    service {'httpd':
      ensure => 'stopped',
      enable => false
      }

  } else {

    if($::srv_httpd == 'enabled') {
      notify { 'httpd':
        message  => $message,
        loglevel => $loglevel,
      }
    }
  }
}
