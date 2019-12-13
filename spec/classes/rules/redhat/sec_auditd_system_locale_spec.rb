require 'spec_helper'

enforce_options = [true, false]
arch_options = ['x86_64', 'i686']

describe 'security_baseline::rules::redhat::sec_auditd_system_locale' do
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
                  'system-locale' => false,
                },
              },
            }
          end
          let(:params) do
            {
              'enforce' => enforce,
              'message' => 'sec_auditd_actions test',
              'log_level' => 'warning',
            }
          end

          it { is_expected.to compile }

          if enforce
            it {
              is_expected.to contain_file_line('watch network environment rule 1')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/audit/rules.d/sec_baseline_auditd.rules',
                  'line'   => '-a always,exit -F arch=b32 -S sethostname,setdomainname -F key=system-locale',
                )
                .that_notifies('Exec[reload auditd rules]')

              is_expected.to contain_file_line('watch network environment rule 2')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/audit/rules.d/sec_baseline_auditd.rules',
                  'line'   => '-w /etc/issue -p wa -k system-locale',
                )
                .that_notifies('Exec[reload auditd rules]')

              is_expected.to contain_file_line('watch network environment rule 3')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/audit/rules.d/sec_baseline_auditd.rules',
                  'line'   => '-w /etc/issue.net -p wa -k system-locale',
                )
                .that_notifies('Exec[reload auditd rules]')

              is_expected.to contain_file_line('watch network environment rule 4')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/audit/rules.d/sec_baseline_auditd.rules',
                  'line'   => '-w /etc/hosts -p wa -k system-locale',
                )
                .that_notifies('Exec[reload auditd rules]')

              is_expected.to contain_file_line('watch network environment rule 5')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/audit/rules.d/sec_baseline_auditd.rules',
                  'line'   => '-w /etc/sysconfig/network -p wa -k system-locale',
                )
                .that_notifies('Exec[reload auditd rules]')

              is_expected.to contain_file_line('watch network environment rule 6')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/audit/rules.d/sec_baseline_auditd.rules',
                  'line'   => '-w /etc/sysconfig/network-scripts -p wa -k system-locale',
                )
                .that_notifies('Exec[reload auditd rules]')

              if arch == 'x86_64'
                is_expected.to contain_file_line('watch network environment rule 7')
                  .with(
                    'ensure' => 'present',
                    'path'   => '/etc/audit/rules.d/sec_baseline_auditd.rules',
                    'line'   => '-a always,exit -F arch=b64 -S sethostname,setdomainname -F key=system-locale',
                  )
                  .that_notifies('Exec[reload auditd rules]')
              else
                is_expected.not_to contain_file_line('watch network environment rule 7')
              end

              is_expected.not_to contain_echo('auditd-locale')
            }

          else
            it {
              is_expected.not_to contain_file_line('watch network environment rule 1')
              is_expected.not_to contain_file_line('watch network environment rule 2')
              is_expected.not_to contain_file_line('watch network environment rule 3')
              is_expected.not_to contain_file_line('watch network environment rule 4')
              is_expected.not_to contain_file_line('watch network environment rule 5')
              is_expected.not_to contain_file_line('watch network environment rule 6')
              is_expected.not_to contain_file_line('watch network environment rule 7')
              is_expected.to contain_echo('auditd-locale')
                .with(
                  'message'  => 'Auditd has no rule to collect events modifying network environment.',
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
