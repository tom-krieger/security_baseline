require 'spec_helper'

describe 'security_baseline::rules::common::sec_legacy_plus_shadow' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'security_baseline' => {
            'legacy_plus' => {
              'shadow' => 'zgt',
            },
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'legacy plus shadow',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        is_expected.to contain_echo('legacy-plus-shadow')
          .with(
            'message'  => 'legacy plus shadow',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      }
    end
  end
end
