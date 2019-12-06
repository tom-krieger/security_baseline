require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_auditd_init' do
  on_supported_os.each do |os, _os_facts|
    enforce_options.each do |enforce|
      context "on #{os}" do
        let(:pre_condition) do
          <<-EOF
          class { 'security_baseline':
            baseline_version => '1.0.0',
            rules => {},
            logfile => '/opt/puppetlabs/facter/facts.d/security_baseline_findings.yaml',
            auditd_rules_file => '/etc/audit/rules.d/sec_baseline_auditd.rules',
          }

          EOF
        end
        let(:facts) do
          {
            security_baseline: {
              auditd: {
              },
            },
          }
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'sec_auditd_init test',
            'log_level' => 'warning',
            'buffer_size' => 8192,
          }
        end

        it { is_expected.to compile }
        it {
          if enforce
            is_expected.to contain_file('/etc/audit/rules.d/sec_baseline_auditd.rules')
              .with(
                'ensure' => 'present',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0750',
              )
            is_expected.to contain_file_line('auditd init delete rules')
              .with(
                'ensure'  => 'present',
                'path'    => '/etc/audit/rules.d/sec_baseline_auditd.rules',
                'line'    => '-D',
              )
              .that_requires('File[/etc/audit/rules.d/sec_baseline_auditd.rules]')

            is_expected.to contain_file_line('auditd init set buffer')
              .with(
                'ensure'  => 'present',
                'path'    => '/etc/audit/rules.d/sec_baseline_auditd.rules',
                'line'    => '-b 8192',
              )
              .that_requires('File[/etc/audit/rules.d/sec_baseline_auditd.rules]')
          else
            is_expected.not_to contain_file('/etc/audit/rules.d/sec_baseline_auditd.rules')
            is_expected.not_to contain_file_line('auditd init delete rules')
            is_expected.not_to contain_file_line('auditd init set buffer')
          end
        }
      end
    end
  end
end
