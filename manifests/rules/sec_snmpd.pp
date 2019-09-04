# @summary 
#    Ensure SNMP Server is not enabled (Scored)
#
# The Simple Network Management Protocol (SNMP) server is used to listen for SNMP commands from 
# an SNMP management system, execute the commands or collect the information and then send 
# results back to the requesting system.
#
# Rationale:
# The SNMP server can communicate using SNMP v1, which transmits data in the clear and does not 
# require authentication to execute commands. Unless absolutely necessary, it is recommended that 
# the SNMP service not be used. If SNMP is required the server should be configured to 
# disallow SNMP v1.
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
#   class security_baseline::rules::sec_snmpd {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_snmpd (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    service {'snmpd':
      ensure => 'stopped',
      enable => false
    }

  } else {

    if($::srv_snmpd == 'enabled') {
      echo { 'snmpd':
        message   => $message,
        log_level => $log_level,
        withpath  => false,
      }
    }
  }
}
