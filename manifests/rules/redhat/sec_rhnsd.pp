# @summary 
#    Disable the rhnsd Daemon (Not Scored)
#
# The rhnsd daemon polls the Red Hat Network web site for scheduled actions and, if there are, executes those actions.
#
# Rationale:
# Patch management policies may require that organizations test the impact of a patch before it is deployed in 
# a production environment. Having patches automatically deployed could have a negative impact on the environment. 
# It is best to not allow an action by default but only after appropriate consideration has been made. It is 
# recommended that the service be disabled unless the risk is understood and accepted or you are running your own 
# satellite . This item is not scored because organizations may have addressed the risk.
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
#   class security_baseline::rules::redhat::sec_rhnsd {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_rhnsd (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if( $enforce) {

    ensure_resource('service', ['rhnsd'], {
      ensure => stopped,
      enable => false,
    })

  } else {

    if($facts['security_baseline']['services_enabled']['srv_rhnsd'] != 'disabled') {

      echo { 'rhnsd':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }

    }

  }
}
