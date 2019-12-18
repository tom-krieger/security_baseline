require 'spec_helper'

describe 'security_baseline::rules::common::sec_audit_suid_programs' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'Audit suid programs',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        is_expected.to contain_echo('suid-programs')
          .with(
            'message'  => 'Audit suid programs',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      }
    end
  end
end
