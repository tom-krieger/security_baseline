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
#   class security_baseline::rules::sles::sec_httpd {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sles::sec_httpd (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    service {'apache2':
      ensure => 'stopped',
      enable => false
      }

  } else {

    if($facts['security_baseline']['services_enabled']['srv_apache2'] == 'enabled') {
      echo { 'apache2':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
