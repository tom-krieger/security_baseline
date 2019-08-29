Facter.add('kmod_cramfs') do
  confine :kernel => 'Linux'
  setcode do
    installed = Facter::Core::Execution.exec('lsmod | grep cramfs')
    if installed.empty?
      false
    else
      true
    end
  end
end
