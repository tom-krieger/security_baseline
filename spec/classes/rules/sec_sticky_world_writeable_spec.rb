require 'spec_helper'

describe 'security_baseline::rules::sec_sticky_world_writeable' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'sticky_ww' => 'available',
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
