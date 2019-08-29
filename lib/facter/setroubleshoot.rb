# frozen_string_literal: true

# setroubleshoot.rb
# Check if setroubleshoot package is installed

Facter.add('setroubleshoot_pkg') do
  confine :osfamily => 'RedHat'
  setcode do
      val = Facter::Core::Execution.exec("rpm -q setroubleshoot")
      if val.empty? or val =~ %r{not installed} then
        false
      else
        true
      end
  end
end
