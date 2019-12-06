require 'spec_helper'

describe 'security_baseline::sec_check' do
  let(:title) { '1.1.1' }

  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:pre_condition) { <<-EOF
        class { 'security_baseline': 
          baseline_version => '1.0.0',
          rules => {},
          logfile => '/opt/puppetlabs/facter/facts.d/security_baseline_findings.yaml',
          auditd_rules_file => '/etc/audit/rules.d/sec_baseline_auditd.rules',
          reporting_type  => 'fact',
          debug => true,
        }
        EOF
      }
      let(:facts) { os_facts }
      let(:params) do
        {
          'rulename' => 'cramfs',
          'description' => 'Support for cramfs removed',
          'enforce' => true,
          'class' => '::security_baseline::sec_cramfs',
          'check' => {
            'fact_name' => 'kmod_cramfs',
            'fact_value' => false,
          },
        }
      end

      it { is_expected.to compile }
      it {
        #is_expected.to contain_echo('Applying rule cramfs')
        #  .with(
        #    'loglevel' => 'debug',
        #    'withpath' => false,
        #  )

        # is_expected.to create_class('security_baseline::sec_cramfs')
      }
    end
  end
end
