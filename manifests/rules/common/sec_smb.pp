# @summary 
#    Ensure DHCP Server is not enabled (Scored)
#
# The Samba daemon allows system administrators to configure their Linux systems to share file 
# systems and directories with Windows desktops. Samba will advertise the file systems and 
# directories via the Small Message Block (SMB) protocol. Windows desktop users will be able to 
# mount these directories and file systems as letter drives on their systems.
# 
# Rationale:
# If there is no need to mount directories and file systems to Windows systems, then this service 
# can be disabled to reduce the potential attack surface.
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
#   class security_baseline::rules::common::sec_smb {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_smb (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    Service {'smb':
      ensure => 'stopped',
      enable => false
    }

  } else {

    if($facts['security_baseline']['services_enabled']['srv_smb'] == 'enabled') {
      echo { 'smb':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
