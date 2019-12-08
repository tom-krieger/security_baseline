require 'spec_helper'

describe 'security_baseline::rules::common::sec_legacy_plus_passwd' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'security_baseline' => {
            'legacy_plus' => {
              'passwd' => 'zgt',
            },
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'legacy plus passwd',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        is_expected.to contain_echo('legacy-plus-passwd')
          .with(
            'message'  => 'legacy plus passwd',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      }
    end
  end
end
