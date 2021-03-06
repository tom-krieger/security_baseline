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
#   class security_baseline::rules::redhat::sec_service_tftp {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_service_tftp (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {
    if($facts['operatingsystemmajrelease'] > '6') {

      ensure_resource('service', ['tftp-dgram', 'tftp-stream'], {
        ensure => stopped,
        enable => false,
      })
    } else {
      ensure_resource('service', ['tftp'], {
        ensure => stopped,
        enable => false,
      })
    }
  } else {
    if($facts['security_baseline']['xinetd_services']['srv_tftp'] == true) {
      echo { 'tftp-service':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
