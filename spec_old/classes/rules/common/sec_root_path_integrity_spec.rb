require 'spec_helper'

describe 'security_baseline::rules::common::sec_root_path_integrity' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      it { is_expected.to compile }
    end
  end
end
