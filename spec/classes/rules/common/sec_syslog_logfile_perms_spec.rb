require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_syslog_logfile_perms' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'syslog' => {
                'log_status' => 'nok',
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'log file permissions',
            'log_level' => 'warning',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_file('/var/log')
              .with(
                'ensure'  => 'directory',
                'recurse' => true,
                'mode'    => 'g-wx,o-rwx',
                'ignore'  => ['puppetlabs', 'puppet'],
              )

            is_expected.not_to contain_echo('aisyslog-log-file-permsde')
          else
            is_expected.not_to contain_file('/var/log')
            is_expected.to contain_echo('syslog-log-file-perms')
              .with(
                'message'  => 'log file permissions',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
