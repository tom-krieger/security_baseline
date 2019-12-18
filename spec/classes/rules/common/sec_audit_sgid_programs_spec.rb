require 'spec_helper'

describe 'security_baseline::rules::common::sec_audit_sgid_programs' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'Audit sgid programs',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        is_expected.to contain_echo('sgid-programs')
          .with(
            'message'  => 'Audit sgid programs',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      }
    end
  end
end
