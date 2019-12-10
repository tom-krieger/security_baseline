require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_selinux_state' do
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
            'selinux_config_mode' => 'disabled',
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'selinux config mode',
            'log_level' => 'warning',
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
            
            is_expected.to contain_file_line('selinux_enforce')
              .with(
                'path'     => '/etc/selinux/config',
                'line'     => 'SELINUX=enforcing',
                'match'    => 'SELINUX=',
                'multiple' => true,
              )

            is_expected.not_to contain_echo('selinux_enforce')
          else
            is_expected.not_to contain_file('/etc/selinux/config')
            is_expected.not_to contain_file_line('selinux_enforce')
            is_expected.to contain_echo('selinux_enforce')
              .with(
                'message'  => 'selinux config mode',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
