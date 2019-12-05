require 'spec_helper'

describe 'security_baseline::rules::redhat::sec_hfs' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }
      let(:params) do
        {
          'enforce' => true,
          'message' => 'hfs',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        is_expected.to contain_kmod__install('hfs')
          .with(
            command: '/bin/true',
          )
      end
    end
  end
end
