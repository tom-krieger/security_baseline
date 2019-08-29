require 'spec_helper'

describe 'security_baseline::rules::sec_talk_client' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'talk_pkg' => true,
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'talk client package',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
