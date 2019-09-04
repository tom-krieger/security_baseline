Facter.add('sticky_ww') do
  confine kernel: 'Linux'
  setcode do
    Facter::Core::Execution.exec("df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null")
  end
end
