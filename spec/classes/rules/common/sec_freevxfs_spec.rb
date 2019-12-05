require 'spec_helper'

describe 'security_baseline::rules::common::sec_freevxfs' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }
      let(:params) do
        {
          'enforce' => true,
          'message' => 'freevxfs',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        is_expected.to contain_kmod__install('freevxfs')
          .with(
            command: '/bin/true',
          )
      end
    end
  end
end
