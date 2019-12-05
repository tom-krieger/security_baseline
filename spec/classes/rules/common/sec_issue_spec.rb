require 'spec_helper'

describe 'security_baseline::rules::common::sec_issue' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'issue' => 1234,
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'motd configuration',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
