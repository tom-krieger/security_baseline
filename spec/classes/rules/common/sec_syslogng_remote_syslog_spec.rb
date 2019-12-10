require 'spec_helper'

enforce_options = [true, false]
loghost_options = [true, false]

describe 'security_baseline::rules::common::sec_syslogng_remote_syslog' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      loghost_options.each do |is_loghost|
        param = !is_loghost
        context "on #{os} with loghost #{is_loghost} enforce = #{enforce}" do
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
                    'loghost' => param,
                  },
                },
              },
            )
          end
          let(:params) do
            {
              'enforce' => enforce,
              'message' => 'syslog-ng remote syslog host',
              'log_level' => 'warning',
              'is_loghost' => is_loghost,
            }
          end

          it { is_expected.to compile }
          it do
            if enforce
              if is_loghost
                is_expected.to contain_file_line('syslog-ng remote 1')
                  .with(
                    'ensure' => 'present',
                    'path'   => '/etc/syslog-ng/syslog-ng.conf',
                    'line'   => 'source net{ tcp(); };',
                    'match'  => '^source net',
                  )
                  .that_notifies('Exec[reload-syslog-ng]')

                is_expected.to contain_file_line('syslog-ng remote 2')
                  .with(
                    'ensure' => 'present',
                    'path'   => '/etc/syslog-ng/syslog-ng.conf',
                    'line'   => 'destination remote { file("/var/log/remote/${FULLHOST}-log"); };',
                    'match'  => '^destination remote',
                  )
                  .that_notifies('Exec[reload-syslog-ng]')

                is_expected.to contain_file_line('syslog-ng remote 3')
                  .with(
                    'ensure' => 'present',
                    'path'   => '/etc/syslog-ng/syslog-ng.conf',
                    'line'   => 'log { source(net); destination(remote); };',
                  )
                  .that_notifies('Exec[reload-syslog-ng]')
              else
                is_expected.to contain_file_line('syslog-ng remote 1')
                  .with(
                    'ensure' => 'present',
                    'path'   => '/etc/syslog-ng/syslog-ng.conf',
                    'line'   => '',
                    'match'  => '^source net',
                  )
                  .that_notifies('Exec[reload-syslog-ng]')

                is_expected.to contain_file_line('syslog-ng remote 2')
                  .with(
                    'ensure' => 'present',
                    'path'   => '/etc/syslog-ng/syslog-ng.conf',
                    'line'   => '',
                    'match'  => '^destination remote',
                  )
                  .that_notifies('Exec[reload-syslog-ng]')
              end
              is_expected.not_to contain_echo('syslogng-remote-syslog-host')
            else
              is_expected.not_to contain_file_line('syslog-ng remote 1')
              is_expected.not_to contain_file_line('syslog-ng remote 2')
              if is_loghost
                is_expected.not_to contain_file_line('syslog-ng remote 3')
              end
              is_expected.to contain_echo('syslogng-remote-syslog-host')
                .with(
                  'message'  => 'syslog-ng remote syslog host',
                  'loglevel' => 'warning',
                  'withpath' => false,
                )

            end
          end
        end
      end
    end
  end
end
