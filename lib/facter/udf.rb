Facter.add('kmod_udf') do
  confine :kernel => 'Linux'
  setcode do
    installed = Facter::Core::Execution.exec('lsmod | grep udf')
    if installed.empty?
      false
    else
      true
    end
  end
end
