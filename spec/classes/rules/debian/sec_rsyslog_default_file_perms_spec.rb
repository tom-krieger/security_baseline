require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_rsyslog_default_file_perms' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce}" do
      let(:pre_condition) do
        <<-EOF
        exec { 'reload-rsyslogd':
          command     => 'pkill -HUP rsyslogd',
          path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          refreshonly => true,
        }
        EOF
      end
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          'security_baseline' => {
            'syslog' => {
              'rsyslog' => {
                'filepermissions' => '0755',
              },
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'rsyslog file permissions',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_file_line('rsyslog-filepermissions')
            .with(
              'ensure' => 'present',
              'path'   => '/etc/rsyslog.conf',
              'line'   => '$FileCreateMode 0640',
              'match'  => '^\$FileCreateMode.*',
            )
            .that_notifies('Exec[reload-rsyslogd]')

          is_expected.to contain_file('/etc/rsyslog.d/')
            .with(
              'ensure'  => 'directory',
              'recurse' => true,
              'mode'    => '0640',
            )

          is_expected.not_to contain_echo('rsyslog-file-permissions')
        else
          is_expected.not_to contain_file_line('rsyslog-filepermissions')
          is_expected.not_to contain_file('/etc/rsyslog.d/')
          is_expected.to contain_echo('rsyslog-file-permissions')
            .with(
              'message'  => 'rsyslog file permissions',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
