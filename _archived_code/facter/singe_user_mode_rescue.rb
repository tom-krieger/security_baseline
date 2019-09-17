# frozen_string_literal: true

# single_user_mode.rb
# Check if /sbin/sulogin is used propperly

Facter.add('single_user_mode_rescue') do
  confine kernel: 'Linux'
  setcode do
    resc = Facter::Core::Execution.exec('grep /sbin/sulogin /usr/lib/systemd/system/rescue.service')
    if resc.empty?
      false
    else
      true
    end
  end
end
