require 'spec_helper'

describe 'security_baseline::rules::common::sec_unconfigured_services' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'security_baseline' => {
            'unconfigured_services' => 'test1',
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'unconfigured services',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        is_expected.to contain_echo('unconfigured-services')
          .with(
            'message'  => 'unconfigured services',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      end
    end
  end
end
