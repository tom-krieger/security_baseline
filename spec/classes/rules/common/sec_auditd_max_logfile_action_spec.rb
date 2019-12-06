require 'spec_helper'

enforce_options = [true, false]
arch_options = ['x86_64', 'i686']

describe 'security_baseline::rules::common::sec_auditd_max_logfile_action' do
  on_supported_os.each do |os, _os_facts|
    enforce_options.each do |enforce|
      arch_options.each do |arch|
        context "on #{os} with enforce = #{enforce} and arch = #{arch}" do
          let(:pre_condition) do
            <<-EOF
            class { 'security_baseline':
              baseline_version => '1.0.0',
              rules => {},
              logfile => '/opt/puppetlabs/facter/facts.d/security_baseline_findings.yaml',
              auditd_rules_file => '/etc/audit/rules.d/sec_baseline_auditd.rules',
            }

            exec { 'reload auditd rules':
              refreshonly => true,
              command     => "auditctl -R ${security_baseline::auditd_rules_file}",
              path        => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
            }
            EOF
          end
          let(:facts) do
            {
              architecture: arch.to_s,
              security_baseline: {
                auditd: {
                  'max_log_file_action' => 'none',
                },
              },
            }
          end
          let(:params) do
            {
              'enforce' => enforce,
              'message' => 'sec_auditd_actions test',
              'log_level' => 'warning',
              'max_log_file_action' => 'keep_logs',
            }
          end

          it { is_expected.to compile }

          if enforce
            it {
              is_expected.to contain_file_line('auditd_max_log_file_action')
                .with(
                  'path'  => '/etc/audit/auditd.conf',
                  'line'  => 'max_log_file_action = keep_logs',
                  'match' => '^max_log_file_action',
                )

              is_expected.not_to contain_echo('auditd-max-log-action')
            }

          else
            it {
              is_expected.not_to contain_file_line('auditd_max_log_file_action')
              is_expected.to contain_echo('auditd-max-log-action')
                .with(
                  'message'  => 'Auditd setting for max_log_file_action is not correct.',
                  'loglevel' => 'warning',
                  'withpath' => false,
                )
            }
          end
        end
      end
    end
  end
end
