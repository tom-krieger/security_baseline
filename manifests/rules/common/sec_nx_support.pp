# @summary 
#    Ensure XD/NX support is enabled (Not Scored)
#
# Recent processors in the x86 family support the ability to prevent code execution on a per memory page basis. Generically 
# and on AMD processors, this ability is called No Execute (NX), while on Intel processors it is called Execute Disable (XD). 
# This ability can help prevent exploitation of buffer overflow vulnerabilities and should be activated whenever possible. 
# Extra steps must be taken to ensure that this protection is enabled, particularly on 32-bit x86 systems. Other processors, 
# such as Itanium and POWER, have included such support since inception and the standard kernel for those platforms supports 
# the feature.
#
# Rationale:
# Enabling any feature that can protect against buffer overflow attacks enhances the security of the system.
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
#   class security_baseline::rules::common::sec_nx_support {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_nx_support (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {

  } else {

    if($facts['security_baseline']['nx'] != 'protected') {
      echo { 'nx-support':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
