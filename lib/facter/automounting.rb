Facter.add('automounting') do
  confine :kernel => 'Linux'
  # If autofs is not installed this will return:
  #  Failed to get unit file state for autofs.service: No such file or directory
  #
  # If it is installed it and is diabled it will return:
  #  disabled
  #
  # Probably this should be parsed and returned as a boolean
  setcode 'systemctl is-enabled autofs'
end