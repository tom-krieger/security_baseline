require 'spec_helper'

describe 'security_baseline::rules::debian::sec_service_openbsd_inetd' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      it { is_expected.to compile }
    end
  end
end
