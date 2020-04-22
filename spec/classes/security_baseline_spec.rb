require 'spec_helper'

describe 'security_baseline' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }
      let(:params) do
        {
          'baseline_version' => '1.0.0',
          'reboot' => true,
          'reboot_timeout' => 120,
          'debug' => true,
          'log_info' => true,
          'dry_run' => false,
          'rules' => {
            '1.1.1.1' => {
              'rulename' => 'cramfs',
              'active' => true,
              'scored' => true,
              'level' => 1,
              'description' => 'Support for cramfs removed',
              'enforce' => true,
              'class' => 'security_baseline::rules::common::sec_cramfs',
              'check' => {
                'fact_hash' => 'security_baseline',
                'fact_name' => ['kernel_modules', 'cramfs'],
                'fact_value' => false,
              },
              'message' => 'Test message unit test',
              'log_level' => 'warning,',
              'reboot' => false,
            },
          },
        }
      end

      it {
        is_expected.to compile.with_all_deps

        is_expected.to create_class('security_baseline::services')
        is_expected.to create_class('security_baseline::config')
        is_expected.to create_class('security_baseline::system_file_permissions_cron')
        is_expected.to create_class('security_baseline::world_writeable_files_cron')
        is_expected.to create_class('security_baseline::unowned_files_cron')
        is_expected.to create_class('security_baseline::auditd_suid_rules_cron')
        is_expected.to contain_concat('/opt/puppetlabs/facter/facts.d/security_baseline_findings.yaml')
          .with(
            'ensure' => 'present',
            'owner'  => 'root',
            'group'  => 'root',
            'mode'   => '0644',
          )
        is_expected.to contain_concat__fragment('start')
          .with(
            'target'  => '/opt/puppetlabs/facter/facts.d/security_baseline_findings.yaml',
            'order'   => 1,
          )

        is_expected.to contain_concat__fragment('finish')
          .with(
            'target'  => '/opt/puppetlabs/facter/facts.d/security_baseline_findings.yaml',
            'order'   => 9999,
          )

        is_expected.to contain_echo('Applying security baseline version: 1.0.0')
          .with(
            'loglevel' => 'debug',
            'withpath' => false,
          )

        is_expected.to contain_security_baseline__sec_check('1.1.1.1')
      }
    end
  end
end
