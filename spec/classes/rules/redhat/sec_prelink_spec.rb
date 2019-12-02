require 'spec_helper'

describe 'security_baseline::rules::redhat::sec_prelink' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      # prelink_pkg
      let(:facts) do
        os_facts.merge(
          'prelink_pkg' => true,
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'sctp configuration',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
