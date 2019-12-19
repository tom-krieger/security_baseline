require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_sudo_logfile' do
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
            'message' => 'sudo logfile',
            'log_level' => 'warning',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_file_line('sudo logfile')
              .with(
                'path'               => '/etc/sudoers',
                'match'              => 'Defaults.*logfile\s*=',
                'append_on_no_match' => true,
                'line'               => 'Defaults logfile="/var/log/sudo.log"',
              )

            is_expected.not_to contain_echo('sudo-logfile')
          else
            is_expected.not_to contain_file_line('sudo logfile')
            is_expected.to contain_echo('sudo-logfile')
              .with(
                'message'  => 'sudo logfile',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
