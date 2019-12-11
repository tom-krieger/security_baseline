require 'spec_helper'

describe 'security_baseline::rules::common::sec_ntp_usage' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'security_baseline' => {
            'ntp' => {
              'chrony_status' => false,
              'ntp_status' => false,
              'ntp_use' => 'unused',
            },
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'ntp usage',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        is_expected.to contain_echo('ntp-usage')
          .with(
            'message'  => 'ntp usage',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      }
    end
  end
end
