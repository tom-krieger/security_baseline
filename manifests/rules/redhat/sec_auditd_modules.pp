# @summary 
#    Ensure kernel module loading and unloading is collected (Scored)
#
# Monitor the loading and unloading of kernel modules. The programs insmod (install a kernel module), 
# rmmod (remove a kernel module), and modprobe (a more sophisticated program to load and unload modules, 
# as well as some other features) control loading and unloading of modules. The init_module (load a module) 
# and delete_module (delete a module) system calls control loading and unloading of modules. Any execution 
# of the loading and unloading module programs and system calls will trigger an audit record with an 
# identifier of "modules".
#
# Rationale:
# Monitoring the use of insmod , rmmod and modprobe could provide system administrators with evidence that 
# an unauthorized user loaded or unloaded a kernel module, possibly compromising the security of the system. 
# Monitoring of the init_module and delete_module system calls would reflect an unauthorized user attempting 
# to use a different program to load and unload modules.
#
# @param enforce
#    Sets rule enforcemt. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @param message
#    Message to print into the log
#
# @param log_level
#    Loglevel for the message
#
# @param level
#    Profile level
#
# @param scored
#    Indicates if a rule is scored or not
#
# @example
#   class { 'security_baseline::rules::redhat::sec_auditd_modules':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline::rules::redhat::sec_auditd_modules (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    file_line { 'watch modules rule 1':
      ensure => present,
      path   => $secutity_baseline::auditd_rules_file,
      line   => '-w /sbin/insmod -p x -k modules',
    }
    file_line { 'watch modules rule 2':
      ensure => present,
      path   => $secutity_baseline::auditd_rules_file,
      line   => '-w /sbin/rmmod -p x -k modules',
    }
    file_line { 'watch modules rule 3':
      ensure => present,
      path   => $secutity_baseline::auditd_rules_file,
      line   => '-w /sbin/modprobe -p x -k modules',
    }
    if($facts['architecture'] == 'x86_64') {
      file_line { 'watch modules rule 4':
        ensure => present,
        path   => $secutity_baseline::auditd_rules_file,
        line   => '-a always,exit -F arch=b64 -S init_module -S delete_module -k modules',
      }
    } else {
      file_line { 'watch modules rule 4':
        ensure => present,
        path   => $secutity_baseline::auditd_rules_file,
        line   => '-a always,exit -F arch=b32 -S init_module -S delete_module -k modules',
      }
    }
  } else {
    if($facts['security_baseline']['auditd']['modules'] == false) {
      echo { 'auditd-modules':
        message  => 'Auditd has no rule to collect kernel module loading and unloading events.',
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
