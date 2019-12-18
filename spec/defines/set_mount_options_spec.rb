require 'spec_helper'

describe 'security_baseline::set_mount_options' do
  let(:title) { '/tmp-noexec' }
  let(:params) do
    {
      'mountpoint'   => '/tmp',
      'mountoptions' => 'noexec',
    }
  end

  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      it { is_expected.to compile }
    end
  end
end
