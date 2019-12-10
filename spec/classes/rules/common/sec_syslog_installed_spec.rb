require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_syslog_installed' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with rsyslogd and enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'syslog' => {
                'syslog_installed' => false,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'syslog installed',
            'log_level' => 'warning',
            'syslog_daemon' => 'rsyslog',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_package('rsyslog')
              .with(
                'ensure' => 'installed',
              )
            is_expected.not_to contain_echo('syslog-installed')
          else
            is_expected.not_to contain_package('rsyslog')
            is_expected.to contain_echo('syslog-installed')
              .with(
                'message'  => 'syslog installed',
                'loglevel' => 'warning',
                'withpath' => false,
              )

          end
        end
      end

      context "on #{os} with syslog-ng and enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'syslog' => {
                'syslog_installed' => false,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'syslog installed',
            'log_level' => 'warning',
            'syslog_daemon' => 'syslog-ng',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_package('syslog-ng')
              .with(
                'ensure' => 'installed',
              )
            is_expected.not_to contain_echo('syslog-installed')
          else
            is_expected.not_to contain_package('syslog-ng')
            is_expected.to contain_echo('syslog-installed')
              .with(
                'message'  => 'syslog installed',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
