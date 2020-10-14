# @summary 
#    Ensure /dev/shm is configured (Scored)
#
# /dev/shm is a traditional shared memory concept. One program will create a memory portion, which other processes 
# (if permitted) can access. If /dev/shm is not configured, tmpfs will be mounted to /dev/shm by systemd.
#
# Rationale:
# Any user can upload and execute files inside the /dev/shm similar to the /tmp partition. Configuring /dev/shm allows an administrator 
# to set the noexec option on the mount, making /dev/shm useless for an attacker to install executable code. It would also prevent an 
#ä attacker from establishing a hardlink to a system setuid program and wait for it to be updated. Once the program was updated, the 
# hardlink would be broken and the attacker would have his own copy of the program. If the program happened to have a security 
# vulnerability, the attacker could continue to exploit the known flaw.
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
#   class security_baseline::rules::common::sec_dev_shm_partition {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_dev_shm_partition (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
) {
  if (has_key($facts, 'security_baseline')) and
    ($facts['security_baseline']['partitions']['shm']['partition'] == undef) {

    echo { 'dev-shm-partition':
      message  => $message,
      loglevel => $log_level,
      withpath => false,
    }
  }
}
