# frozen_string_literal: true

# security_patches.rb
# Fact containing all security patches

Facter.add('security_patches') do
  confine :osfamily => 'RedHat'
  setcode 'yum check-update --security -q | grep -v ^$'
end
