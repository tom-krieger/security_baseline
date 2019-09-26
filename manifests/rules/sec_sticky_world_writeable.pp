# @summary 
#    Ensure sticky bit is set on all world-writable directories (Scored)
#
# Setting the sticky bit on world writable directories prevents users from deleting or renaming files in 
# that directory that are not owned by them.
#
# Rationale:
# This feature prevents the ability to delete or rename files in world writable directories (such as /tmp ) 
# that are owned by another user.
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
#   class security_baseline::rules::sec_sticky_world_writeable {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_sticky_world_writeable (
  $enforce = true,
  String $message = '',
  String $log_level = ''
) {

  if $facts['security_baseline']['sticky_ww'] != 'none' {

    if $enforce {
      exec { "df --local -P | awk {'if (NR!=1) print \$6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null|xargs chmod a+t":
          path => '/bin/',
        }

    } else {

      echo { 'sticky-ww':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }

    }
  }
}
