require 'spec_helper'

describe 'security_baseline::auditd_suid_rules_cron' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
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
      end
    end
  end
end
