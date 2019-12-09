require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_rsyslog_remote_logs' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:pre_condition) do
          <<-EOF
          exec { 'reload-rsyslog':
            command     => 'pkill -HUP rsyslog',
            path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            refreshonly => true,
          }
          EOF
        end
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'syslog' => {
                'rsyslog' => {
                  'filepermissions' => '0755',
                  'remotesyslog' => 'none',
                },
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'rsyslog remote log host',
            'log_level' => 'warning',
            'remote_log_host' => '10.10.10.10',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_file_line('rsyslog-remote-log-host')
              .with(
                'ensure' => 'present',
                'path'   => '/etc/rsyslog.conf',
                'line'   => '*.* @@10.10.10.10',
                'match'  => '^\*\.\* \@\@.*',
              )
              .that_notifies('Exec[reload-rsyslog]')

            is_expected.not_to contain_echo('rsyslog-remote-log-host')
          else
            is_expected.not_to contain_file_line('rsyslog-remote-log-host')
            is_expected.to contain_echo('rsyslog-remote-log-host')
              .with(
                'message'  => 'rsyslog remote log host',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
