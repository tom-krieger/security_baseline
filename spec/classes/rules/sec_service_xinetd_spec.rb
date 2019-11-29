require 'spec_helper'

describe 'security_baseline::rules::redhat::sec_service_xinetd' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'srv_xinetd' => true,
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'service xinetd',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
