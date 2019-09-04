require 'spec_helper'

describe 'security_baseline::rules::sec_tmp_partition' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'tmp_partition' => '/tmp',
          'tmp_nodev' => false,
          'tmp_noexec' => false,
          'tmp_nosuid' => false,
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'telnet service',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
