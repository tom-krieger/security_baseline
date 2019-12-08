require 'spec_helper'

describe 'security_baseline::rules::common::sec_legacy_plus_group' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'security_baseline' => {
            'legacy_plus' => {
              'group' => 'zgt',
            },
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'legacy plus group',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        is_expected.to contain_echo('legacy-plus-group')
          .with(
            'message'  => 'legacy plus group',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      }
    end
  end
end
