# @summary 
#    Ensure default user umask is 027 or more restrictive (Scored)
#
# The default umask determines the permissions of files created by users. The user creating the 
# file has the discretion of making their files and directories readable by others via the chmod 
# command. Users who wish to allow their files and directories to be readable by others by default 
# may choose a different default umask by inserting the umask command into the standard shell 
# configuration files ( .profile , .bashrc , etc.) in their home directories.
#
# Rationale:
# Setting a very secure default value for umask ensures that users make a conscious choice about their 
# file permissions. A default umask setting of 077 causes files and directories created by users to not 
# be readable by any other user on the system. A umask of 027 would make files and directories readable 
# by users in the same Unix group, while a umask of 022 would make files readable by every user on the system.
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
# @param max_pass_days
#    Password expires after days
#
# @example
#   class security_baseline::rules::sles::sec_umask_setting {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::sles::sec_umask_setting (
  Boolean $enforce            = true,
  String $message             = '',
  String $log_level           = '',
  String $default_umask       = '027',
) {
  if($enforce) {
    file_line { 'bashrc':
      path     => '/etc/bash.bashrc',
      line     => "      umask ${default_umask}",
      match    => '^\s+umask\s+\d+',
      multiple => true,
    }
    file_line { 'profile':
      path     => '/etc/profile',
      line     => "    umask ${default_umask}",
      match    => '^\s+umask\s+\d+',
      multiple => true,
    }
    file_line { 'login.defs':
      path  => '/etc/login.defs',
      line  => "UMASK           ${default_umask}",
      match => '^\s+umask\s+\d+',
    }
  } else {
    if($facts['security_baseline']['umask']) {
      echo { 'umask-setting':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
