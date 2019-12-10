require 'spec_helper'

describe 'security_baseline::logging' do
  let(:title) { '1.1.1' }
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
        concat { '/opt/puppetlabs/facter/facts.d/security_baseline_findings.yaml':
          ensure => present,
          owner  => 'root',
          group  => 'root',
          mode   => '0644',
        }
        EOF
      end
      let(:facts) { os_facts }
      let(:params) do
        {
          'rulenr' => '1.1.1',
          'rule' => 'cramfs',
          'desc' => 'Support for cramfs removed',
          'log_level' => 'warning',
          'msg' => 'Test message',
          'rulestate' => 'compliant',
          'level' => 1,
          'scored' => true,
          'reporting_type' => 'fact',
        }
      end

      it {
        is_expected.to compile
        is_expected.to contain_concat__fragment('1.1.1')
      }
    end
  end
end
