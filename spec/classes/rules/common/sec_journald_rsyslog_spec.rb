require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_journald_rsyslog' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'journald' => {
                'forward_to_syslog' => 'none',
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'journald forward to syslog',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_file_line('enable syslog forwarding')
              .with(
                'path'  => '/etc/systemd/journald.conf',
                'match' => 'ForwardToSyslog=',
                'line'  => 'ForwardToSyslog=yes',
              )

            is_expected.not_to contain_echo('journald-forward-rsyslog')
          else
            is_expected.not_to contain_line('enable syslog forwarding')
            is_expected.to contain_echo('journald-forward-rsyslog')
              .with(
                'message'  => 'journald forward to syslog',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
