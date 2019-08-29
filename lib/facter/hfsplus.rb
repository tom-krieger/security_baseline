Facter.add('kmod_hfsplus') do
  confine :kernel => 'Linux'  
  setcode do
    installed = Facter::Core::Execution.exec('lsmod | grep hfsplus')
    if installed.empty?
      false
    else
      true
    end
  end
end
