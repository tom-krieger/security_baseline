Facter.add('kmod_squashfs') do
  confine :kernel => 'Linux'
  setcode do
    installed = Facter::Core::Execution.exec('lsmod | grep squashfs')
    if installed.empty?
      false
    else
      true
    end
  end
end
  