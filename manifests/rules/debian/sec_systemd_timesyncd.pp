# @summary 
#    Ensure systemd-timesyncd is configured (Not Scored)
#
# systemd-timesyncd is a daemon that has been added for synchronizing the system clock across the network. It 
# implements an SNTP client. In contrast to NTP implementations such as chrony or the NTP reference server this 
# only implements a client side, and does not bother with the full NTP complexity, focusing only on querying time 
# from one remote server and synchronizing the local clock to it. The daemon runs with minimal privileges, and 
# has been hooked up with networkd to only operate when network connectivity is available. The daemon saves the 
# current clock to disk every time a new NTP sync has been acquired, and uses this to possibly correct the system 
# clock early at bootup, in order to accommodate for systems that lack an RTC such as the Raspberry Pi and embedded 
# devices, and make sure that time monotonically progresses on these systems, even if it is not always correct. To 
# make use of this daemon a new system user and group "systemd- timesync" needs to be created on installation of 
# systemd.
#
# Note: The systemd-timesyncd service specifically implements only SNTP. This minimalistic service will set the system 
#       clock for large offsets or slowly adjust it for smaller deltas. More complex use cases are not covered by 
#       systemd-timesyncd.
#
# This recommendation only applies if timesyncd is in use on the system.
#
# Rationale:
# Proper configuration is vital to ensuring time synchronization is working properly.
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
# @param ntp_servers
#    The ntp server to use for time synchonisation.
#
# @param ntp_fallback_servers
#
# @example
#   class security_baseline::rules::debian::sec_systemd_timesyncd {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#       ntp_servers => ['0.de.pool.ntp.org', '1.de.pool.ntp.org', '3.de.pool.ntp.org'],
#       ntp_fallback_servers => ['3.de.pool.ntp.org'],
#   }
#
# @api private
class security_baseline::rules::debian::sec_systemd_timesyncd  (
  Boolean $enforce            = true,
  String $message             = '',
  String $log_level           = '',
  Array $ntp_servers          = [],
  Array $ntp_fallback_servers = [],
) {
  if ($enforce) {
    if(empty($ntp_servers)) {
      fail('no ntp servers specified!')
    } else {
      $servers = join($ntp_servers, ' ')
      file_line { 'ntp-timesyncd.conf':
        path               => '/etc/systemd/timesyncd.conf',
        line               => "NTP=${servers}",
        match              => '^NTP=',
        append_on_no_match => true,
      }
    }

    if(!empty($ntp_fallback_servers)) {
      $fallback = join($ntp_fallback_servers, ' ')
      file_line { 'ntp-fallback-timesyncd.conf':
        path               => '/etc/systemd/timesyncd.conf',
        line               => "FallbackNTP=${fallback}",
        match              => '^FallbackNTP=',
        append_on_no_match => true,
      }
    }

  } else {
    if($facts['security_baseline']['services_enabled']['systemd-timesyncd'] != 'enabled') {
      echo { 'systemd_timesyncd':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
