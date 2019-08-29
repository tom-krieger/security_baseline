# frozen_string_literal: true

# yum_repolist.rb

Facter.add('yum_repolist') do
  confine :osfamily => 'RedHat'
  setcode do
    Facter::Core::Execution.exec('yum repolist')
  end
end