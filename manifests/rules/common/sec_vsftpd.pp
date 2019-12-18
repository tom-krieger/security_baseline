# @summary 
#    Ensure FTP Server is not enabled (Scored)
#
# The File Transfer Protocol (FTP) provides networked computers with the ability to transfer files.
#
# Rationale:
# FTP does not protect the confidentiality of data or authentication credentials. It is recommended 
# sftp be used if file transfer is required. Unless there is a need to run the system as a FTP server 
# (for example, to allow anonymous downloads), it is recommended that the service be disabled to reduce 
# the potential attack surface.
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
#   class security_baseline::rules::common::sec_vsftpd {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_vsftpd (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {

    service {'vsftpd':
      ensure => 'stopped',
      enable => false,
    }

  } else {

    if($facts['security_baseline']['services_enabled']['srv_vsftpd'] == 'enabled') {
      echo { 'vsftpd':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
