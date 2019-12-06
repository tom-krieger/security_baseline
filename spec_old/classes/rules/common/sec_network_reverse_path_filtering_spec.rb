require 'spec_helper'

describe 'security_baseline::rules::common::sec_network_reverse_path_filtering' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'network_parameters' => {
            'net.ipv4.conf.all.rp_filter' => '0',
            'net.ipv4.conf.default.rp_filter' => '0',
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'reverse path filtering configuration',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
