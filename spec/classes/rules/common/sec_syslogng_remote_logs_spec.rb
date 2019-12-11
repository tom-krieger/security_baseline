require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_syslogng_remote_logs' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce} and remote syslog host" do
        let(:pre_condition) do
          <<-EOF
          exec { 'reload-syslog-ng':
            command     => 'pkill -HUP syslog-ng',
            path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            refreshonly => true,
          }
          EOF
        end
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'syslog' => {
                'syslog-ng' => {
                  'filepermissions' => '0777',
                  'remotesyslog' => 'none',
                  'loghost' => false,
                },
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'syslog-ng sent to remote log host',
            'log_level' => 'warning',
            'remote_log_host' => '10.10.10.10',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_file_line('syslog-ng remote_log_host')
              .with(
                'ensure' => 'present',
                'path'   => '/etc/syslog-ng/syslog-ng.conf',
                'line'   => 'destination logserver { tcp("10.10.10.10" port(514)); }; log { source(src); destination(logserver); };',
                'match'  => '^destination logserver',
              )
              .that_notifies('Exec[reload-syslog-ng]')

            is_expected.not_to contain_echo('syslogng-remote-log-host')
          else
            is_expected.not_to contain_file_line('syslog-ng remote_log_host')
            is_expected.to contain_echo('syslogng-remote-log-host')
              .with(
                'message'  => 'syslog-ng sent to remote log host',
                'loglevel' => 'warning',
                'withpath' => false,
              )

          end
        end
      end

      context "on #{os} with enforce = #{enforce} without remote syslog host" do
        let(:pre_condition) do
          <<-EOF
          exec { 'reload-syslog-ng':
            command     => 'pkill -HUP syslog-ng',
            path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            refreshonly => true,
          }
          EOF
        end
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'syslog' => {
                'syslog-ng' => {
                  'filepermissions' => '0777',
                  'remotesyslog' => 'none',
                  'loghost' => false,
                },
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'syslog-ng sent to remote log host',
            'log_level' => 'warning',
            'remote_log_host' => '',
          }
        end

        it { is_expected.to compile }
        it do
          is_expected.not_to contain_file_line('syslog-ng remote_log_host')
          if enforce
            is_expected.not_to contain_echo('syslogng-remote-log-host')
          else
            is_expected.to contain_echo('syslogng-remote-log-host')
              .with(
                'message'  => 'syslog-ng sent to remote log host',
                'loglevel' => 'warning',
                'withpath' => false,
              )

          end
        end
      end
    end
  end
end
