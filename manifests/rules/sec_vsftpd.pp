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
# @param loglevel
#    The loglevel for the above message
#
# @example
#   class security_baseline::rules::sec_vsftpd {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_vsftpd (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    service {'vsftpd':
      ensure => 'stopped',
      enable => false,
    }

  } else {

    if($::srv_vsftpd == 'enabled') {
      echo { 'vsftpd':
        message  => $message,
        loglevel => $loglevel,
        withpath => false,
      }
    }
  }
}
