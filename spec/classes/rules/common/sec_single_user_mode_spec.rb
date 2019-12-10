require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_single_user_mode' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'single_user_mode' => {
                'emergency' => false,
                'rescue' => false,
                'status' => false,
              },
            },
            'selinux_config_mode' => 'disabled',
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'single user mode',
            'log_level' => 'warning',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_file_line('su-rescue')
              .with(
                'path'  => '/usr/lib/systemd/system/rescue.service',
                'line'  => 'ExecStart=-/bin/sh -c \"/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\"',
                'match' => '^ExecStart=',
              )

            is_expected.to contain_file_line('su-emergency')
              .with(
                'path'  => '/usr/lib/systemd/system/emergency.service',
                'line'  => 'ExecStart=-/bin/sh -c \"/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\"',
                'match' => '^ExecStart=',
              )

            is_expected.not_to contain_echo('single_user_mode')
          else
            is_expected.not_to contain_file_line('su-rescue')
            is_expected.not_to contain_file_line('su-emergency')
            is_expected.to contain_echo('single_user_mode')
              .with(
                'message'  => 'single user mode',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
