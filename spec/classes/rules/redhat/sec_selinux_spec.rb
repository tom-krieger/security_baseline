require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_selinux' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'selinux' => {
                'bootloader' => false,
              },
              'packages_installed' => {
                'libselinux' => false,
              },
            },
            'selinux_config_mode' => 'disabled',
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'selinux package',
            'log_level' => 'warning',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_package('libselinux')
              .with(
                'ensure' => 'present',
              )

            is_expected.not_to contain_echo('selinux-pkg')
          else
            is_expected.not_to contain_package('libselinux')
            is_expected.to contain_echo('selinux-pkg')
              .with(
                'message'  => 'selinux package',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
