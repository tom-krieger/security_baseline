# @summary 
#    Change mount options
#
# Change the mount options of a mountpoint using mounttab module.
#
# @param mountpoint
#    Mountpoint to work on
#
# @param mountoptions
#    Options to set
#
# @example
#   security_baseline::mount_options { 
#     mountpoint => '/home',
#     mountoptions => 'nodev', 
# }
define security_baseline::mount_options (
  String $mountpoint,
  String $mountoptions,
) {
  mounttab { $mountpoint:
    ensure   => present,
    options  => $mountoptions,
    provider => augeas,
    notify   => Exec["remount ${mountpoint} with ${mountoptions}"],
  }

  exec { "remount ${mountpoint} with ${mountoptions}":
    command     => "mount -o remount ${mountpoint}",
    path        => ['/bn', '/usr/bin', '/sbin', '/uasr/sbin'],
    refreshonly => true,
  }

}
