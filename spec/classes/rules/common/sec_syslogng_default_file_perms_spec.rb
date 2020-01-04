require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_syslogng_default_file_perms' do
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
            'message' => 'syslog-ng file permissions',
            'log_level' => 'warning',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_file_line('syslog-ng permissions')
              .with(
                'ensure' => 'present',
                'path'   => '/etc/syslog-ng/syslog-ng.conf',
                'line'   => "options { flush_lines (0); time_reopen (10); log_fifo_size (1000); chain_hostnames(off); flush_lines(0); \
perm(0640); stats_freq(3600); threaded(yes); use_dns (no); use_fqdn (no); create_dirs (yes); keep_hostname (yes);};",
              )
              .that_notifies('Exec[reload-syslog-ng]')

            is_expected.not_to contain_echo('syslogng-file-permissions')
          else
            is_expected.not_to contain_file_line('syslog-ng permissions')
            is_expected.to contain_echo('syslogng-file-permissions')
              .with(
                'message'  => 'syslog-ng file permissions',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
