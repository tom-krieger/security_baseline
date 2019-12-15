require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::sles::sec_restrict_su' do
  enforce_options.each do |enforce|
    context "on Suse with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Suse',
          operatingsystem: 'SLES',
          architecture: 'x86_64',
          'security_baseline' => {
            'pam' => {
              'wheel' => 'none',
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'su command restriction',
          'log_level' => 'warning',
          'wheel_users' => ['root'],
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_pam('pam-su-restrict')
            .with(
              'ensure'    => 'present',
              'service'   => 'su',
              'type'      => 'auth',
              'control'   => 'required',
              'module'    => 'pam_wheel.so',
              'arguments' => ['use_uid'],
            )
          is_expected.to contain_exec('root_wheel')
            .with(
              'command' => 'usermod -G wheel root',
              'unless'  => 'grep wheel /etc/group | grep root',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            )

          is_expected.not_to contain_echo('restrict-su')
        else
          is_expected.not_to contain_pam('pam-su-restrict')
          is_expected.not_to contain_exec('root_wheel')
          is_expected.to contain_echo('restrict-su')
            .with(
              'message'  => 'su command restriction',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
