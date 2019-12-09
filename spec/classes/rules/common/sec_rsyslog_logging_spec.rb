require 'spec_helper'

enforce_options = [true]

describe 'security_baseline::rules::common::sec_rsyslog_logging' do
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
                },
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'rsyslog logging config',
            'log_level' => 'warning',
            'log_config' => {
              'emerg' => {
                'src' => '*.emerg',
                'dst' => '*.emerg',
              },
              'mailall' => {
                'src' => 'mail.*',
                'dst' => '-/var/log/mail',
              },
            },
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_file('/etc/rsyslog.d/emerg.conf')
              .with(
                'ensure'  => 'present',
                'content' => '*.emerg *.emerg',
              )
              .that_notifies('Exec[reload-rsyslog]')

            is_expected.to contain_file('/etc/rsyslog.d/mailall.conf')
              .with(
                'ensure'  => 'present',
                'content' => 'mail.* -/var/log/mail',
              )
              .that_notifies('Exec[reload-rsyslog]')
          else
            is_expected.not_to contain_file('/etc/rsyslog.d/emerg.conf')
            is_expected.not_to contain_file('/etc/rsyslog.d/mailall.conf')
          end
        end
      end
    end
  end
end
