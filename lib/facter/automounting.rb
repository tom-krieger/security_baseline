Facter.add('automounting') do
  confine :kernel => 'Linux'
  setcode do
    ret = ''
    autofs = Facter::Core::Execution.exec('systemctl is-enabled autofs')
    if (autofs =~ %r{^Failed}) or (autofs.empty?) then
      ret = 'disabled'
    else
      ret = autofs
    end

    ret
  end
end