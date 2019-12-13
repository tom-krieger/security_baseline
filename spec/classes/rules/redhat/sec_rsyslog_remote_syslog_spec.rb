require 'spec_helper'

enforce_options = [true, false]
loghost_options = [true, false]

describe 'security_baseline::rules::redhat::sec_rsyslog_remote_syslog' do
  enforce_options.each do |enforce|
    loghost_options.each do |is_loghost|
      loghost_param = !is_loghost
      context "on redhat with is_loghost = #{is_loghost} and enforce = #{enforce}" do
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
          {
            osfamily: 'RedHat',
            operatingsystem: 'CentOS',
            architecture: 'x86_64',
            'security_baseline' => {
              'syslog' => {
                'rsyslog' => {
                  'filepermissions' => '0755',
                  'loghost' => loghost_param,
                },
              },
            },
          }
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'rsyslog remote syslog host',
            'log_level' => 'warning',
            'is_loghost' => is_loghost,
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            if is_loghost
              is_expected.to contain_file_line('rsyslog.conf add ModLoad')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/rsyslog.conf',
                  'line'   => '$ModLoad imtcp',
                  'match'  => '\$ModLoad',
                )

              is_expected.to contain_file_line('rsyslog.conf add InputTCPServerRun')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/rsyslog.conf',
                  'line'   => '$InputTCPServerRun 514',
                  'match'  => '\$InputTCPServerRun',
                )
            else
              is_expected.to contain_file_line('rsyslog.conf remove ModLoad')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/rsyslog.conf',
                  'line'   => '#$ModLoad imtcp',
                  'match'  => '\$ModLoad',
                )

              is_expected.to contain_file_line('rsyslog.conf remove InputTCPServerRun')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/rsyslog.conf',
                  'line'   => '#$InputTCPServerRun 514',
                  'match'  => '\$InputTCPServerRun',
                )
            end

            is_expected.not_to contain_echo('rsyslog-remote-syslog')
          else
            if is_loghost
              is_expected.not_to contain_file_line('rsyslog.conf add ModLoad')
              is_expected.not_to contain_file_line('rsyslog.conf add InputTCPServerRun')
            else
              is_expected.not_to contain_file_line('rsyslog.conf remove ModLoad')
              is_expected.not_to contain_file_line('rsyslog.conf remove InputTCPServerRun')
            end

            is_expected.to contain_echo('rsyslog-remote-syslog')
              .with(
                'message'  => 'rsyslog remote syslog host',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
