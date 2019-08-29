# frozen_string_literal: true

# grub_passwd.rb
# Check if bootloader password is set

Facter.add('grub_passwd') do
  confine :kernel => 'Linux'
  setcode do
    grubpwd = Facter::Core::Execution.exec('grep "^GRUB2_PASSWORD" /boot/grub2/grub.cfg')
    if grubpwd.empty?
      false
    else
      true
    end
  end
end
