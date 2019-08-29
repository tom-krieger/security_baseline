Facter.add('kmod_hfs') do
  confine :kernel => 'Linux'
  setcode do
    installed = Facter::Core::Execution.exec('lsmod | grep hfs')
    if installed.empty?
      false
    else
      true
    end
  end
end
