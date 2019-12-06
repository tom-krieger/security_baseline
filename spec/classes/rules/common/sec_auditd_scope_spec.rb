require 'spec_helper'

enforce_options = [true, false]
arch_options = ['x86_64', 'i686']

describe 'security_baseline::rules::common::sec_auditd_scope' do
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
                  scope: false,
                },
              },
            }
          end
          let(:params) do
            {
              'enforce' => enforce,
              'message' => 'sec_auditd_scope test',
              'log_level' => 'warning',
            }
          end

          it { is_expected.to compile }

          if enforce
            it {
              is_expected.to contain_file_line('watch scope rule 1')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/audit/rules.d/sec_baseline_auditd.rules',
                  'line'   => '-w /etc/sudoers -p wa -k scope',
                )
                .that_notifies('Exec[reload auditd rules]')

              is_expected.to contain_file_line('watch scope rule 2')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/audit/rules.d/sec_baseline_auditd.rules',
                  'line'   => '-w /etc/sudoers.d/ -p wa -k scope',
                )
                .that_notifies('Exec[reload auditd rules]')

              is_expected.not_to contain_echo('auditd-scope')
            }

          else
            it {
              is_expected.not_to contain_file_line('watch scope rule 1')
              is_expected.not_to contain_file_line('watch scope rule 2')
              is_expected.to contain_echo('auditd-scope')
                .with(
                  'message'  => 'Auditd has no rule to collect changes to system administration scope (sudoers).',
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
