require 'spec_helper'

describe 'security_baseline::rules::common::sec_nx_support' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'security_baseline' => {
            'nx' => 'unprotected',
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'nx unprotected',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        is_expected.to contain_echo('nx-support')
          .with(
            'message'  => 'nx unprotected',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      }
    end
  end
end
