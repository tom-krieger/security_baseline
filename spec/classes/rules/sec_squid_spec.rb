require 'spec_helper'

describe 'security_baseline::rules::sec_squid' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'srv_squid' => 'enabled',
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'squid service',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
