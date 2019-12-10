# @summary 
#    Audit system file permissions (Not Scored)
#
# The RPM package manager has a number of useful options. One of these, the --verify (or - V ) option, can be used to verify 
# that system packages are correctly installed. The --verify option can be used to verify a particular package or to verify 
# all system packages. If no output is returned, the package is installed correctly.
#
# Rationale:
# It is important to confirm that packaged system files and directories are maintained with the permissions they were 
# intended to have from the OS vendor.
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
#   class security_baseline::rules::common::sec_system_file_perms {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_system_file_perms (
  $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if ($facts['security_baseline']['file_permissions']['system_files_count'] != 0) {
    echo { 'system-file-perms':
      message  => $message,
      loglevel => $log_level,
      withpath => false,
    }
  }
}
