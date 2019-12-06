require 'spec_helper'

describe 'security_baseline::rules::common::sec_home_partition' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'home_nodev' => false,
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'home nodev',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
