require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_sudo_use_pty' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'packages_installed' => {
                'sudo' => false,
              },
              'sudo' => {
                'use_pty' => 'none',
                'logfile' => 'none',
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'sudo use pty',
            'log_level' => 'warning',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_file_line('sudo use pty')
              .with(
                'path'               => '/etc/sudoers',
                'match'              => 'Defaults.*use_pty',
                'append_on_no_match' => true,
                'line'               => 'Defaults use_pty',
              )

            is_expected.not_to contain_echo('sudo-use-pty')
          else
            is_expected.not_to contain_file_line('sudo use pty')
            is_expected.to contain_echo('sudo-use-pty')
              .with(
                'message'  => 'sudo use pty',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
