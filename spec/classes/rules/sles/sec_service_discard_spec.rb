require 'spec_helper'

describe 'security_baseline::rules::sles::sec_service_discard' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'srv_discard' => true,
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'discard service',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
