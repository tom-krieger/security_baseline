require 'spec_helper'

enforce_options = [true, false]
arch_options = ['x86_64', 'i686']

describe 'security_baseline::rules::common::sec_auditd_when_full' do
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
                  action_mail_acct: 'none',
                  admin_space_left_action: 'none',
                  space_left_action: 'none',
                },
              },
            }
          end
          let(:params) do
            {
              'enforce' => enforce,
              'message' => 'sec_auditd_actions test',
              'log_level' => 'warning',
              'space_left_action' => 'email',
              'action_mail_acct' => 'root',
              'admin_space_left_action' => 'halt',
            }
          end

          it { is_expected.to compile }

          if enforce
            it {
              is_expected.to contain_file_line('auditd_space_left_action')
                .with(
                  'line'  => "space_left_action = email",
                  'path'  => '/etc/audit/auditd.conf',
                  'match' => '^space_left_action',
                )

              is_expected.to contain_file_line('auditd_action_mail_acct')
                .with(
                  'line'  => "action_mail_acct = root",
                  'path'  => '/etc/audit/auditd.conf',
                  'match' => '^action_mail_acct',
                )

              is_expected.to contain_file_line('auditd_admin_space_left_action')
                .with(
                  'line'  => "admin_space_left_action = halt",
                  'path'  => '/etc/audit/auditd.conf',
                  'match' => '^admin_space_left_action',
                )

              is_expected.not_to contain_echo('auditd-max-log-size')
            }

          else
            it {
              is_expected.not_to contain_file_line('auditd_space_left_action')
              is_expected.not_to contain_file_line('auditd_action_mail_acct')
              is_expected.not_to contain_file_line('auditd_admin_space_left_action')
              is_expected.to contain_echo('auditd-max-log-size')
                .with(
                  'message'  => 'Auditd setting for action_mail_acct and/or admin_space_left_action and/or space_left_action are not correct',
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
