# frozen_string_literal: true

# yum_gpgcheck.rb
# checks for gpgcheck in /etc/yum.conf

Facter.add('yum_gpgcheck') do
  confine :osfamily => 'RedHat'
  setcode do
    value = Facter::Core::Execution.exec('grep ^gpgcheck /etc/yum.conf')
    if value.empty? then
      false
    else
      if value == 'gpgcheck=1' then
        true
      else
        false
      end
    end
  end
end
