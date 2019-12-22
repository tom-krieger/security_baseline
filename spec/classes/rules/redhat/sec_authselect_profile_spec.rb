require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_authselect_profile' do
  enforce_options.each do |enforce|
    context "RedHat with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          'security_baseline' => {
            'authselect' => {
              'current_options' => ['with-faillock', 'without-nullok'],
              'faillock' => 'none',
              'faillock_global' => 'with_faillock',
              'profile' => 'none',
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'authselect profile',
          'log_level' => 'warning',
          'custom_profile' => 'testprofile',
          'base_profile' => 'sssd',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_exec('set custom profile')
            .with(
              'command' => "authselect create-profile testprofile -b sssd --symlink-meta",
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => "test $(authselect current | grep -c \"Profile ID: custom/testprofile\") -gt 0"
            )
            
          is_expected.not_to contain_echo('authselect-profile')
        else
          is_expected.not_to contain_exec('set custom profile')
          is_expected.to contain_echo('authselect-profile')
            .with(
              'message'  => 'authselect profile',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
