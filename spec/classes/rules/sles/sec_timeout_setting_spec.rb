require 'spec_helper'

describe 'security_baseline::rules::sles::sec_timeout_setting' do
  context 'Suse' do
    let(:facts) { {
      :osfamily => 'Suse',
      :operatingsystem => 'SLES',
      :architecture => 'x86_64',
    } }
    let(:params) do
      {
        'enforce' => true,
        'message' => 'service chargen',
        'loglevel' => 'warning',
        'default_timeout' => 900,
      }
    end

    it { is_expected.to compile }
    it do
      is_expected.to contain_file_line('bashrc_tmout')
        .with(
          'path' => '/etc/bash.bashrc',
          'line' => "TMOUT=900",
        )

      is_expected.to contain_file_line('profile_tmout')
        .with(
          'path' => '/etc/profile',
          'line' => "TMOUT=900",
        )
    end
  end
end
