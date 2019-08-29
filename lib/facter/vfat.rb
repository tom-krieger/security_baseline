Facter.add('kmod_vfat') do
  confine :kernel => 'Linux'
    setcode do
      installed = Facter::Core::Execution.exec('lsmod | grep vfat')
      if installed.empty?
        false
      else
        true
      end
    end
  end
  