Facter.add('kmod_freevxfs') do
  confine :kernel => 'Linux'
  setcode do
    installed = Facter::Core::Execution.exec('lsmod | grep freevxfs')
    if installed.empty?
      false
    else
      true
    end
  end
end
