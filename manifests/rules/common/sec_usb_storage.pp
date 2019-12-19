# @summary 
#    Disable USB Storage (Scored)
#
# USB storage provides a means to transfer and store files insuring persistence and availability of the 
# files independent of network connection status. Its popularity and utility has led to USB-based malware 
# being a simple and common means for network infiltration and a first step to establishing a persistent 
# threat within a networked environment.
#
# Rationale:
# Restricting USB access on the system will decrease the physical attack surface for a device and diminish 
# the possible vectors to introduce malware.
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
#   class security_baseline::rules::common::sec_usb_storage {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_usb_storage (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if $enforce {
    kmod::install { 'usb-storage':
      command => '/bin/true',
    }
  } else {
    if($facts['security_baseline']['kernel_modules']['usb-storage']) {
      echo { 'usb-storage':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
