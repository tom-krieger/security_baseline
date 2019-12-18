# @summary 
#    Ensure nosuid option set on /dev/shm partition (Scored)
#
# The nosuid mount option specifies that the filesystem cannot contain setuid files.
#
# Rationale:
# Setting this option on a file system prevents users from introducing privileged programs onto 
# the system and allowing non-root users to execute them.
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
#   class security_baseline::rules::common::sec_dev_shm_nosuid {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_dev_shm_nosuid (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if $enforce {
    if (
      ($facts['security_baseline']['partitions']['shm']['nosuid'] == false) and
      (has_key($facts['mountpoints'], '/dev/shm'))
    ) {
      if(!defined(File_line['add /dev/shm to fstab'])) {
        file_line { 'add /dev/shm to fstab':
          ensure             => present,
          append_on_no_match => true,
          path               => '/etc/fstab',
          match              => 'tmpfs\s*on\s*/dev/shm\s*type\s*tmpfs',
          line               => 'tmpfs        /dev/shm        tmpfs        defaults,nodev,nosuid,noexec        0 0',
        }
      }
      security_baseline::set_mount_options { '/dev/shm-nosuid':
        mountpoint   => '/dev/shm',
        mountoptions => 'nosuid',
      }
    }
  } else {
    if $facts['security_baseline']['partitions']['shm']['nosuid'] == false {
      echo { 'dev-shm-nosuid':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
