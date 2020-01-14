require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_selinux_policy' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'selinux' => {
                'bootloader' => false,
              },
            },
            'selinux_config_policy' => 'disabled',
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'policy selinux',
            'log_level' => 'warning',
            'selinux_policy' => 'targeted',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_file('/etc/selinux/config')
              .with(
                'ensure' => 'present',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0644',
              )

            is_expected.to contain_file_line('selinux_targeted')
              .with(
                'path'  => '/etc/selinux/config',
                'line'  => 'SELINUXTYPE=targeted',
                'match' => '^SELINUXTYPE=',
              )

            is_expected.not_to contain_echo('selinux')
          else
            is_expected.not_to contain_file('/etc/selinux/config')
            is_expected.not_to contain_file_line('selinux_targeted')
            is_expected.to contain_echo('selinux')
              .with(
                'message'  => 'policy selinux',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
