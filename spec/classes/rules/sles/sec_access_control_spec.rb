require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::sles::sec_access_control' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'apparmor' => {
                'bootloader' => false,
              },
              'access_control' => 'none',
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' =>  'neither apparmor nor selinux installed',
            'log_level' => 'warning',
            'access_control_pkg' => 'libselinux1',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_package('libselinux1')
              .with(
                'ensure' => 'present',
              )

            is_expected.not_to contain_echo('selinux-apparmor-pkg')
          else
            is_expected.not_to contain_package('libselinux1')
            is_expected.to contain_echo('selinux-apparmor-pkg')
              .with(
                'message'  => 'neither apparmor nor selinux installed',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
