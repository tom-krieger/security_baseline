# @summary 
#    Ensure GDM login banner is configured (Scored)
#
# GDM is the GNOME Display Manager which handles graphical login for GNOME based systems.
#
# Rationale:
# Warning messages inform users who are attempting to login to the system of their legal 
# status regarding the system and must include the name of the organization that owns the 
# system and any monitoring policies that are in place.

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
#   class security_baseline::rules::sles::sec_gdm {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sles::sec_gdm (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($facts['security_baseline']['gnome_gdm']) {

    if($enforce) {

      file { 'gdm':
        ensure  => present,
        path    => '/etc/dconf/profile/gdm',
        content => "user-db:user\nsystem-db:gdm\nfile-db:/usr/share/gdm/greeter-dconf-defaults",
      }

      file { 'banner-login':
        ensure  => present,
        path    => '/etc/dconf/db/gdm.d/01-banner-message',
        content => "[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text=\'Authorized uses only. All activity may be monitored and reported.\'", #lint:ignore:140chars
        require => File['gdm'],
        notify  => Exec['dconf-gdm-exec'],
      }

      exec { 'dconf-gdm-exec':
        path        => '/bin/',
        command     => 'dconf update',
        refreshonly => true,
      }

    } else {

      if($facts['security_baseline']['gnome_gdm_conf'] == false) {
        echo { 'gdm-conf':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
    }
  }
}
