require 'spec_helper'

describe 'security_baseline::rules::redhat::sec_service_echo' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'srv_echo' => true,
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'echo service',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
