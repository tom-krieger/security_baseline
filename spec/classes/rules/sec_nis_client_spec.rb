require 'spec_helper'

describe 'security_baseline::rules::redhat::sec_nis_client' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'ypbind_pkg' => true,
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'ypbind package',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
