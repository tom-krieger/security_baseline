require 'spec_helper'

describe 'security_baseline::rules::common::sec_net_dccp' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'net_dccp' => true,
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'dccp configuration',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
