# @summary 
#    Ensure tftp server is not enabled (Scored)
#
# Trivial File Transfer Protocol (TFTP) is a simple file transfer protocol, typically used to 
# automatically transfer configuration or boot machines from a boot server. The package 
# tftp-server is used to define and support a TFTP server.
#
# Rationale:
# TFTP does not support authentication nor does it ensure the confidentiality or integrity of 
# data. It is recommended that TFTP be removed, unless there is a specific need for TFTP. In 
# that case, extreme caution must be used when configuring the services.
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
#   class security_baseline::rules::debian::sec_service_tftp {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::debian::sec_service_tftp (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if(has_key($facts['security_baseline']['inetd_services'], 'srv_chargen')) {
    if($enforce) {
      if($facts['security_baseline']['inetd_services']['srv_tftp']['status']) {
        file_line { 'tftp_disable':
          line     => 'disable     = yes',
          path     => $facts['security_baseline']['inetd_services']['srv_tftp']['filename'],
          match    => 'disable.*=',
          multiple => true,
        }
      }
    } else {
      if($facts['security_baseline']['inetd_services']['srv_tftp']['status']) {
        echo { 'tftp-inetd':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
    }
  }
}
