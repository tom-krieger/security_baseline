require 'spec_helper'

describe 'security_baseline::summary_result' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:pre_condition) do
        <<-EOF
        class { 'security_baseline':
          baseline_version => '1.0.0',
          rules => {},
          logfile => '/opt/puppetlabs/facter/facts.d/security_baseline_findings.yaml',
          auditd_rules_file => '/etc/audit/rules.d/sec_baseline_auditd.rules',
          reporting_type  => 'fact',
          debug => true,
        }
        EOF
      end
      let(:facts) { os_facts }
      let(:params) do
        {
        }
      end

      it {
        is_expected.to compile
      }
    end
  end
end
