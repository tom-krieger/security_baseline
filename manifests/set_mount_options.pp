# @summary 
#    Change mount options
#
# Change the mount options of a mountpoint.
#
# @param mountpoint
#    Mountpoint to work on
#
# @param mountoptions
#    Options to set
#
# @example
#   security_baseline::set_mount_options { 
#     mountpoint => '/home',
#     mountoptions => 'nodev', 
# }
define security_baseline::set_mount_options (
  String $mountpoint,
  String $mountoptions,
) {
  augeas{ "/etc/fstab - work on ${mountpoint} with ${mountoptions}":
    context => '/files/etc/fstab',
    changes => [
      "ins opt after /files/etc/fstab/*[file = '${mountpoint}']/opt[last()]",
      "set *[file = '${mountpoint}']/opt[last()] ${mountoptions}",
    ],
    onlyif  => "match *[file = '${mountpoint}']/opt[. = '${mountoptions}'] size == 0",
    notify  => Exec["remount ${mountpoint} with ${mountoptions}"],
  }

  exec { "remount ${mountpoint} with ${mountoptions}":
    command     => "mount -o remount ${mountpoint}",
    path        => ['/bn', '/usr/bin', '/sbin', '/uasr/sbin'],
    refreshonly => true,
  }

}
