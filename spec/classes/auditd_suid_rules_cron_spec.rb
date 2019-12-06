require 'spec_helper'

describe 'security_baseline::auditd_suid_rules_cron' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:pre_condition) do
        <<-EOF
        class { 'security_baseline':
          baseline_version => '1.0.0',
          rules => {},
          logfile => '/opt/puppetlabs/facter/facts.d/security_baseline_findings.yaml',
          auditd_rules_file => '/etc/audit/rules.d/sec_baseline_auditd.rules',
          auditd_suid_include => ['/usr'],
          auditd_suid_exclude => [],
        }
        EOF
      end
      let(:facts) { os_facts }

      it { is_expected.to compile }

      it do
        is_expected.to contain_concat('/etc/cron.daily/suid-audit')
          .with(
            'ensure' => 'present',
            'owner'  => 'root',
            'group'  => 'root',
            'mode'   => '0700',
          )

        is_expected.to contain_concat__fragment('suid_cron_top')
          .with(
            'target' => '/etc/cron.daily/suid-audit',
            'source' => 'puppet:///modules/security_baseline/suid_auditd_top',
            'order'  => 01,
          )

        is_expected.to contain_concat__fragment('suid_cron_body')
          .with(
            'target'  => '/etc/cron.daily/suid-audit',
            'order'   => 10,
          )

        is_expected.to contain_concat__fragment('suid_cron_end')
          .with(
            'target' => '/etc/cron.daily/suid-audit',
            'source' => 'puppet:///modules/security_baseline/suid_auditd_end',
            'order'  => 99,
          )
      end
    end

    context "on #{os} with error" do
      let(:pre_condition) do
        <<-EOF
        class { 'security_baseline':
          baseline_version => '1.0.0',
          rules => {},
          logfile => '/opt/puppetlabs/facter/facts.d/security_baseline_findings.yaml',
          auditd_rules_file => '/etc/audit/rules.d/sec_baseline_auditd.rules',
          auditd_suid_include => ['/usr'],
          auditd_suid_exclude => ['/tmp'],
        }
        EOF
      end
      let(:facts) { os_facts }

      it { 
        is_expected.to compile.and_raise_error(/Please include directories or exclude them but you can not do both!/)
      }
    end
  end
end
