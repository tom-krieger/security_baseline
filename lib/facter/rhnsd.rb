# frozen_string_literal: true

# rhnsd.rb
# Ensures there are no duplicate UIDs in /etc/passwd
Facter.add('rhnsd') do
  confine :osfamily => 'RedHat'
  setcode do
    ret = ''
    rhnsd = Facter::Core::Execution.exec('systemctl is-enabled rhnsd')
    if (rhnsd =~ %r{^Failed}) or (rhnsd.empty?) then
      ret = 'disabled'
    else
      ret = rhnsd
    end

    ret
  end
end
