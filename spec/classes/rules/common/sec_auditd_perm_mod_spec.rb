require 'spec_helper'

enforce_options = [true, false]
arch_options = ['x86_64', 'i686']

describe 'security_baseline::rules::common::sec_auditd_perm_mod' do
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
                  'perm-mod' => false,
                },
              },
            }
          end
          let(:params) do
            {
              'enforce' => enforce,
              'message' => 'sec_auditd_perm_mod test',
              'log_level' => 'warning',
            }
          end

          it { is_expected.to compile }

          if enforce
            it {
              is_expected.to contain_file_line('watch perm mod rule 1')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/audit/rules.d/sec_baseline_auditd.rules',
                  'line'   => '-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod',
                )
                .that_notifies('Exec[reload auditd rules]')

              is_expected.to contain_file_line('watch perm mod rule 2')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/audit/rules.d/sec_baseline_auditd.rules',
                  'line'   => '-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod',
                )
                .that_notifies('Exec[reload auditd rules]')

              is_expected.to contain_file_line('watch perm mod rule 3')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/audit/rules.d/sec_baseline_auditd.rules',
                  'line'   => '-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod',
                )
                .that_notifies('Exec[reload auditd rules]')

              if arch == 'x86_64'
                is_expected.to contain_file_line('watch perm mod rule 4')
                  .with(
                    'ensure' => 'present',
                    'path'   => '/etc/audit/rules.d/sec_baseline_auditd.rules',
                    'line'   => '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod',
                  )
                  .that_notifies('Exec[reload auditd rules]')

                is_expected.to contain_file_line('watch perm mod rule 5')
                  .with(
                    'ensure' => 'present',
                    'path'   => '/etc/audit/rules.d/sec_baseline_auditd.rules',
                    'line'   => '-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod',
                  )
                  .that_notifies('Exec[reload auditd rules]')

                is_expected.to contain_file_line('watch perm mod rule 6')
                  .with(
                    'ensure' => 'present',
                    'path'   => '/etc/audit/rules.d/sec_baseline_auditd.rules',
                    'line'   => '-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod',
                  )
                  .that_notifies('Exec[reload auditd rules]')
              else
                is_expected.not_to contain_file_line('watch perm mod rule 4')
                is_expected.not_to contain_file_line('watch perm mod rule 5')
                is_expected.not_to contain_file_line('watch perm mod rule 6')
              end

              is_expected.not_to contain_echo('auditd-perm-mod')
            }

          else
            it {
              is_expected.not_to contain_file_line('watch perm mod rule 1')
              is_expected.not_to contain_file_line('watch perm mod rule 2')
              is_expected.not_to contain_file_line('watch perm mod rule 3')
              is_expected.not_to contain_file_line('watch perm mod rule 4')
              is_expected.not_to contain_file_line('watch perm mod rule 5')
              is_expected.not_to contain_file_line('watch perm mod rule 6')
              is_expected.to contain_echo('auditd-perm-mod')
                .with(
                  'message'  => 'Auditd has no rule to collect discretionary access control permission modification events.',
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
