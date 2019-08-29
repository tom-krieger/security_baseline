Facter.add('automounting') do
  confine :kernel => 'Linux'
  setcode 'systemctl is-enabled autofs'
end