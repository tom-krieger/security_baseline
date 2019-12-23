# @summary 
#    Ensure default zone is set (Scored)
#
# A firewall zone defines the trust level for a connection, interface or source address binding. This is a one 
# to many relation, which means that a connection, interface or source can only be part of one zone, but a zone 
# can be used for many network connections, interfaces and sources.
#
# The default zone is the zone that is used for everything that is not explicitely bound/assigned to another zone.
#
# That means that if there is no zone assigned to a connection, interface or source, only the default zone is used. 
# The default zone is not always listed as being used for an interface or source as it will be used for it either way. 
# This depends on the manager of the interfaces.
#
# Connections handled by NetworkManager are listed as NetworkManager requests to add the zone binding for the 
# interface used by the connection. Also interfaces under control of the network service are listed also because the 
# service requests it.
#
# Rationale:
# Because the default zone is the zone that is used for everything that is not explicitly bound/assigned to another 
# zone, it is important for the default zone to set
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
# @param default_zone
#    firewalld default zone
#
# @example
#   class security_baseline::rules::redhat::sec_firewalld_default_zone {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#       default_zone => 'private',
#   }
#
# @api private
class security_baseline::rules::redhat::sec_firewalld_default_zone (
  Boolean $enforce     = true,
  String $message      = '',
  String $log_level    = '',
  String $default_zone = 'public',
) {
  if ($enforce) {
    if(has_key($facts['security_baseline'], 'firewalld')) {
      if ($facts['security_baseline']['firewalld']['default_zone'] != $default_zone) {
        exec { 'set firewalld default zone':
          command => "firewall-cmd --set-default-zone=${default_zone}",
          path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
        }
      }
    }
  } else {
    if ($facts['security_baseline']['firewalld']['default_zone_status'] == false) {
      echo { 'firewalld-default-zone':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
