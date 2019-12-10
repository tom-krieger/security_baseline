require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_syslogng_logging' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
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
            'message' => 'syslog installed',
            'log_level' => 'warning',
            'log_config' => [
              'log { source(src); source(chroots); filter(f_console); destination(console); };',
              'log { source(src); source(chroots); filter(f_console); destination(xconsole); };',
            ],
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_file_line('syslog-ng logs log { source(src); source(chroots); filter(f_console); destination(console); };')
              .with(
                'ensure' => 'present',
                'path'   => '/etc/syslog-ng/syslog-ng.conf',
                'line'   => 'log { source(src); source(chroots); filter(f_console); destination(console); };',
              )
              .that_notifies('Exec[reload-syslog-ng]')

            is_expected.to contain_file_line('syslog-ng logs log { source(src); source(chroots); filter(f_console); destination(xconsole); };')
              .with(
                'ensure' => 'present',
                'path'   => '/etc/syslog-ng/syslog-ng.conf',
                'line'   => 'log { source(src); source(chroots); filter(f_console); destination(xconsole); };',
              )
              .that_notifies('Exec[reload-syslog-ng]')
          else
            is_expected.not_to contain_file_line('syslog-ng logs log { source(src); source(chroots); filter(f_console); destination(console); };')
            is_expected.not_to contain_file_line('syslog-ng logs log { source(src); source(chroots); filter(f_console); destination(xconsole); };')
          end
        end
      end
    end
  end
end
