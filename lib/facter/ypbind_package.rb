# frozen_string_literal: true

# ypbind_package.rb
# Check if ypbind package is installed

Facter.add('ypbind_pkg') do
  confine :osfamily => 'RedHat'
  setcode do
      val = Facter::Core::Execution.exec("rpm -q ypbind")
      if val.empty? or val =~ %r{not installed} then
        false
      else
        true
      end
  end
end
