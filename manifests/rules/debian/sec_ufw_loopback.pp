# @summary 
#    Ensure loopback traffic is configured (Scored)
#
# Configure the loopback interface to accept traffic. Configure all other interfaces to deny traffic to the 
# loopback network (127.0.0.0/8 for IPv4 and ::1/128 for IPv6).
#
# Rationale:
# Loopback traffic is generated between processes on machine and is typically critical to operation of the 
# system. The loopback interface is the only place that loopback network (127.0.0.0/8 for IPv4 and ::1/128 for IPv6) 
# traffic should be seen, all other interfaces should ignore traffic on this network as an anti-spoofing measure.
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
#   class security_baseline::rules::debian::sec_ufw_loopback {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::debian::sec_ufw_loopback (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
) {
  if ($enforce) {
    exec { 'add allow on lo':
      command => 'ufw allow in on lo',
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => 'test -z "$(ufw status verbose | grep -E \"^Anywhere.*on lo.*ALLOW IN.*Anywhere\")""',
    }
    exec { 'add deny on 127.0.0.0/8':
      command => 'ufw deny in from 127.0.0.0/8',
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => 'test -z "$(ufw status verbose | grep -E \"^Anywhere.*DENY IN.*127.0.0.0/8\")""',
    }
    exec { 'add deny on ::1':
      command => 'ufw deny in from ::1',
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => 'test -z "$(ufw status verbose | grep -E \"^Anywhere (v6).*DENY IN.*::1\")""',
    }
  } else {
    if($facts['security_baseline']['ufw']['loopback_status'] == false) {
      echo { 'ufw-loopback':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
