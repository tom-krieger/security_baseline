require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_rsyslog_installed' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with rsyslogd and enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'syslog' => {
                'syslog_installed' => false,
              },
              'packages_installed' => {
                'rsyslog' => false,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'rsyslog installed',
            'log_level' => 'warning',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_package('rsyslog')
              .with(
                'ensure' => 'present',
              )
            is_expected.not_to contain_echo('rsyslog-installed')
          else
            is_expected.not_to contain_package('rsyslog')
            is_expected.to contain_echo('rsyslog-installed')
              .with(
                'message'  => 'rsyslog installed',
                'loglevel' => 'warning',
                'withpath' => false,
              )

          end
        end
      end
    end
  end
end
