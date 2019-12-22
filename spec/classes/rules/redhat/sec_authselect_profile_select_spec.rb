require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_authselect_profile_select' do
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
              'profile' => 'test',
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'authselect profile select',
          'log_level' => 'warning',
          'custom_profile' => 'testprofile',
          'profile_options' => ['with-sudo', 'with-faillock', 'without-nullok'],
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_exec('select authselect profile')
            .with(
              'command' => 'authselect select custom/testprofile with-sudo with-faillock without-nullok -f',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test ! -d /etc/authselect/custom/testprofile',
              'returns' => [0, 1],
            )

          is_expected.not_to contain_echo('authselect-profile-select')
        else
          is_expected.not_to contain_exec('select authselect profile')
          is_expected.to contain_echo('authselect-profile-select')
            .with(
              'message'  => 'authselect profile select',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
