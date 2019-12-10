require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_syslogng_service' do
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
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_service('syslog-ng')
              .with(
                'ensure' => 'running',
                'enable' => true,
              )
          end
        end
      end
    end
  end
end
