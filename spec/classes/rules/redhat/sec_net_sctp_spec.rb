require 'spec_helper'

describe 'security_baseline::rules::redhat::sec_net_sctp' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'net_sctp' => true,
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'sctp configuration',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
