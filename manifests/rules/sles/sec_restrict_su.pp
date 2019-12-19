# @summary 
#    Ensure access to the su command is restricted (Scored)
#
# The su command allows a user to run a command or shell as another user. The program has been superseded 
# by sudo , which allows for more granular control over privileged access. Normally, the su command can be 
# executed by any user. By uncommenting the pam_wheel.so statement in /etc/pam.d/su , the su command will 
# only allow users in the wheel group to execute su.
#
# Rationale:
# Restricting the use of su , and using sudo in its place, provides system administrators better control of 
# the escalation of user privileges to execute privileged commands. The sudo utility also provides a better 
# logging and audit mechanism, as it can log each command executed via sudo , whereas su can only record that 
# a user executed the su program.
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
# @param wheel_users
#    Users to be added to the wheel group
#
# @example
#   class security_baseline::rules::sles::sec_restrict_su {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::sles::sec_restrict_su (
  Boolean $enforce            = true,
  String $message             = '',
  String $log_level           = '',
  Array $wheel_users          = ['root'],
) {
  if($enforce) {
    pam { 'pam-su-restrict':
        ensure    => present,
        service   => 'su',
        type      => 'auth',
        control   => 'required',
        module    => 'pam_wheel.so',
        arguments => ['use_uid'],
      }

    $wheel_users.each | $user | {
      exec { "${user}_wheel":
        command => "usermod -G wheel ${user}",
        unless  => "grep wheel /etc/group | grep ${user}",
        path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      }
    }
  } else {
    if($facts['security_baseline']['pam']['wheel'] == 'none') {
      echo { 'restrict-su':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
