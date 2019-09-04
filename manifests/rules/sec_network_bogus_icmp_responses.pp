# @summary 
#    Ensure bogus ICMP responses are ignored (Scored)
#
# Setting icmp_ignore_bogus_error_responses to 1 prevents the kernel from logging bogus 
# responses (RFC-1122 non-compliant) from broadcast reframes, keeping file systems from 
# filling up with useless log messages.
#
# Rationale:
# Some routers (and some attackers) will send responses that violate RFC-1122 and attempt 
# to fill up a log file system with many useless error messages.
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
#   class security_baseline::rules::sec_network_bogus_icmp_responses {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_network_bogus_icmp_responses (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    sysctl {
      'net.ipv4.icmp_ignore_bogus_error_responses':
        value => 1
    }

  } else {

    if(has_key($::network_parameters, 'net.ipv4.icmp_ignore_bogus_error_responses')) {
      $fact = $::network_parameters['net.ipv4.icmp_ignore_bogus_error_responses']
    } else {
      $fact = ''
    }
    if($fact != '1') {
      echo { 'net.ipv4.icmp_ignore_bogus_error_responses':
        message   => $message,
        log_level => $log_level,
        withpath  => false,
      }
    }
  }
}
