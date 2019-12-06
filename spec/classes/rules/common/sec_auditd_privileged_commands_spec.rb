require 'spec_helper'

enforce_options = [true, false]
arch_options = ['x86_64', 'i686']

describe 'security_baseline::rules::common::sec_auditd_privileged_commands' do
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
                  'priv-cmds' => false,
                  'priv-cmds-list' => {},
                },
              },
            }
          end
          let(:params) do
            {
              'enforce' => enforce,
              'message' => 'sec_auditd_priv_cmds test',
              'log_level' => 'warning',
            }
          end

          it { is_expected.to compile }

          if enforce
            it {
              is_expected.not_to contain_echo('auditd-priv-cmds')
            }

          else
            it {
              is_expected.to contain_echo('auditd-priv-cmds')
                .with(
                  'message'  => 'Auditd has no rule to collect use of privileged commands.',
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
