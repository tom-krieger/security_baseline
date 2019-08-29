# frozen_string_literal: true

# smb_service.rb
# Check if smb services is enabled

Facter.add('srv_smb') do
  confine :osfamily => 'RedHat'
  setcode do
    ret = ''
    smb = Facter::Core::Execution.exec('systemctl is-enabled smb')
    if (smb =~ %r{^Failed}) or (smb.empty?) then
      ret = 'disabled'
    else
      ret = smb
    end

    ret
  end
end
  