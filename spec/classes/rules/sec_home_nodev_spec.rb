require 'spec_helper'

describe 'security_baseline::rules::redhat::sec_home_nodev' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'home_nodev' => false,
          'home_partition' => '/home',
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
