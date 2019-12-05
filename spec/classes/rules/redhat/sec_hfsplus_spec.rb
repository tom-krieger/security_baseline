require 'spec_helper'

describe 'security_baseline::rules::redhat::sec_hfsplus' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }
      let(:params) do
        {
          'enforce' => true,
          'message' => 'hfsplus',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        is_expected.to contain_kmod__install('hfsplus')
          .with(
            command: '/bin/true',
          )
      end
    end
  end
end
