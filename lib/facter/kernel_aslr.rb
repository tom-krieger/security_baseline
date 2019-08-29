# frozen_string_literal: true

# rkernel_aslr.rb
# Contains the available rpm gpg keys

Facter.add('kernel_aslr') do
  confine :osfamily => 'RedHat'
  setcode do
      val = Facter::Core::Execution.exec("sysctl kernel.randomize_va_space").split(/=/)
      val[1].strip()
  end
end
    