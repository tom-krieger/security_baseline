# frozen_string_literal: true

# rpm_gpg_keys.rb
# Contains the available rpm gpg keys

Facter.add('rpm_gpg_keys') do
  confine :osfamily => 'RedHat'
  # This also doesn't need a do end block
  setcode do
      Facter::Core::Execution.exec("rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n'")
  end
end
    