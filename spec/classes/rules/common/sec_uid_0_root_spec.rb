require 'spec_helper'

describe 'security_baseline::rules::common::sec_uid_0_root' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'security_baseline' => {
            'uid_0' => 'test1',
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'uid 0 root',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        is_expected.to contain_echo('uid_0_root')
          .with(
            'message'  => 'uid 0 root',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      end
    end
  end
end
