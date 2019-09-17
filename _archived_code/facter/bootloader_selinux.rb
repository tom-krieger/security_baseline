# frozen_string_literal: true

# bootloader_selinux.rb
# Check for bootloader entries with disabled selinux. Returns true if no
# entry with selinux=0 or enforcing=0 is found

Facter.add('bootloader_selinux') do
  confine kernel: 'Linux'
  setcode do
    selinux = Facter::Core::Execution.exec('grep "^\s*linux" /boot/grub2/grub.cfg | grep -e "selinux.*=.*0" -e "enforcing.*=.*0"')
    if selinux.empty?
      true
    else
      false
    end
  end
end
