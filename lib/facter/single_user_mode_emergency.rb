# frozen_string_literal: true

# single_user_mode.rb
# Check if /sbin/sulogin is used propperly

Facter.add('single_user_mode_emergency') do
  confine kernel: 'Linux'
  setcode do
    emerg = Facter::Core::Execution.exec('grep /sbin/sulogin /usr/lib/systemd/system/emergency.service')
    if emerg.empty?
      false
    else
      true
    end
  end
end
