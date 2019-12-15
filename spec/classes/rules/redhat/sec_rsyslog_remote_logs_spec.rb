require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_rsyslog_remote_logs' do
  enforce_options.each do |enforce|
    context "on RedHat with enforce = #{enforce} with remote log host" do
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
                'remotesyslog' => 'none',
              },
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'rsyslog remote log host',
          'log_level' => 'warning',
          'remote_log_host' => '10.10.10.10',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_file_line('rsyslog-remote-log-host')
            .with(
              'ensure' => 'present',
              'path'   => '/etc/rsyslog.conf',
              'line'   => '*.* @@10.10.10.10',
              'match'  => '^\*\.\* \@\@.*',
            )
            .that_notifies('Exec[reload-rsyslog]')

          is_expected.not_to contain_echo('rsyslog-remote-log-host')
        else
          is_expected.not_to contain_file_line('rsyslog-remote-log-host')
          is_expected.to contain_echo('rsyslog-remote-log-host')
            .with(
              'message'  => 'rsyslog remote log host',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end

    context "on RedHat with enforce = #{enforce} without remote log host" do
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
                'remotesyslog' => 'none',
              },
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'rsyslog remote log host',
          'log_level' => 'warning',
          'remote_log_host' => '',
        }
      end

      it { is_expected.to compile }
      it do
        is_expected.not_to contain_file_line('rsyslog-remote-log-host')
        if enforce
          is_expected.not_to contain_echo('rsyslog-remote-log-host')
        else
          is_expected.to contain_echo('rsyslog-remote-log-host')
            .with(
              'message'  => 'rsyslog remote log host',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
