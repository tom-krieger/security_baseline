require 'spec_helper'

describe 'security_baseline::rules::common::sec_security_patches' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'security_baseline' => {
            'security_patches' => 'thepackage 1.2.3 rhel',
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'security patches',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        is_expected.to contain_echo('security-patches')
          .with(
            'message'  => 'security patches',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      }
    end
  end
end
