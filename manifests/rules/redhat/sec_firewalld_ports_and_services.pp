# @summary A short summary of the purpose of this class
#
# A description of what this class does
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
# @param expected_services
#    services to be configured in firewalld
#
# @param expected_ports
#    POrts to be configured in firewalld
#
# @example
#   class security_baseline::rules::redhat::sec_firewalld_default_zone {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#       expected_services => ['ssh'],
#       expected_ports => ['25/tcp'],
#   }
#
# @api private
class security_baseline::rules::redhat::sec_firewalld_ports_and_services (
  Boolean $enforce         = true,
  String $message          = '',
  String $log_level        = '',
  Array $expected_services = [],
  Array $expected_ports    = [],
) {
  if ($enforce) {
    $facts['security_baseline']['firewalld']['ports'].each |$port| {
      unless ($port in $expected_ports) {
        exec { "firewalld remove port ${port}":
          command => "firewall-cmd --remove-port=${port}",
          path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
        }
      }
    }

    $facts['security_baseline']['firewalld']['services'].each |$service| {
      unless ($service in $expected_services) {
        exec { "firewalld remove service ${service}":
          command => "firewall-cmd --remove-service=${service}",
          path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
        }
      }
    }
  } else {
    if ($facts['security_baseline']['firewalld']['ports_and_services_status'] == true) {
      echo { 'firewalld-services-ports':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
