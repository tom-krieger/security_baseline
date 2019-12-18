# @summary 
#    Ensure nodev option set on /dev/shm partition (Scored)
#
# The nodev mount option specifies that the filesystem cannot contain special devices.
#
# Rationale:
# Since the /dev/shm filesystem is not intended to support devices, set this option to ensure that users 
# cannot attempt to create special devices in /dev/shm partitions.
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
#   class security_baseline::rules::common::sec_tmp_nodev {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_dev_shm_nodev (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if $enforce {
    if (
      ($facts['security_baseline']['partitions']['shm']['nodev'] == false) and
      (has_key($facts['mountpoints'], '/dev/shm'))
    ) {
      if(!defined(File_line['add /dev/shm to fstab'])) {
        file_line { 'add /dev/shm to fstab':
          ensure             => present,
          append_on_no_match => true,
          path               => '/etc/fstab',
          match              => 'tmpfs\s*on\s*/dev/shm\s*type\s*tmpfs',
          replace            => 'tmpfs        /dev/shm        tmpfs        defaults,nodev,nosuid,noexec        0 0',
        }
      }
      security_baseline::set_mount_options { '/dev/shm-nodev':
        mountpoint   => '/dev/shm',
        mountoptions => 'nodev',
      }
    }
  } else {
    if $facts['security_baseline']['partitions']['shm']['nodev'] == false {
      echo { 'dev-shm-nodev':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
