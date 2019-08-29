# frozen_string_literal: true

# kmod_jffs2.rb
# Check for jffs2 kernel module

Facter.add('kmod_jffs2') do
  confine :kernel => 'Linux'
  setcode do
    installed = Facter::Core::Execution.exec('lsmod | grep jffs2')
    if installed.empty?
      false
    else
      true
    end
  end
end