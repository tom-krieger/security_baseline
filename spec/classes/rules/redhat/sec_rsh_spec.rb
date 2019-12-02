require 'spec_helper'

describe 'security_baseline::rules::redhat::sec_rsh' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'srv_rsh' => 'enabled',
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'rsh service',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
