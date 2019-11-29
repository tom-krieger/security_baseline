require 'spec_helper'

describe 'security_baseline::rules::redhat::sec_sshd_max_auth_tries' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      it { is_expected.to compile }
    end
  end
end
