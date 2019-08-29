require 'spec_helper'

describe 'security_baseline::rules::sec_unconfigured_daemons' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'unconfigured_daemons' => true,
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'unconfigured daemons',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
