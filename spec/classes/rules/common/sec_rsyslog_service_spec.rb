require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_rsyslog_service' do
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
                  'service' => 'disabled',
                },
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'rsyslog service',
            'log_level' => 'warning',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_service('rsyslog')
              .with(
                'ensure' => 'running',
                'enable' => true,
              )

            is_expected.not_to contain_echo('rsyslog-service')
          else
            is_expected.not_to contain_service('rsyslog')
            is_expected.to contain_echo('rsyslog-service')
              .with(
                'message'  => 'rsyslog service',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
