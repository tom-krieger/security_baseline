require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::sles::sec_apparmor_profiles' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'apparmor' => {
                'bootloader' => false,
                'profiles' => 17,
                'profiles_enforced' => 15,
                'profiles_complain' => 2,
              },
              'access_control' => 'none',
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' =>  'apparmor profiles',
            'log_level' => 'warning',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_package('apparmor')
              .with(
                'ensure' => 'present',
              )

            is_expected.to contain_package('apparmor-utils')
              .with(
                'ensure' => 'present',
              )
              .that_requires('Package[apparmor]')

            is_expected.to contain_exec('apparmor enforce')
              .with(
                'command' => 'enforce /etc/apparmor.d/*',
                'path'    => ['/bin', '/sbin', '/usr/bin', '/usr/sbin'],
              )
              .that_requires('Package[apparmor-utils]')

            is_expected.not_to contain_echo('apparmor-profiles')
          else
            is_expected.not_to contain_package('apparmor')
            is_expected.not_to contain_package('apparmor-utils')
            is_expected.not_to contain_exec('apparmor enforce')
            is_expected.to contain_echo('apparmor-profiles')
              .with(
                'message'  => 'apparmor profiles',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
