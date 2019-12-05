require 'spec_helper'

describe 'security_baseline::rules::sles::sec_umask_setting' do
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
        'default_umask' => '027',
      }
    end

    it { is_expected.to compile }
    it do
      is_expected.to contain_file_line('bashrc')
        .with(
          'path'     => '/etc/bash.bashrc',
          'line'     => "      umask 027",
          'match'    => '^\s+umask\s+\d+',
          'multiple' => true,
        )
      is_expected.to contain_file_line('profile')
        .with(
          'path'     => '/etc/profile',
          'line'     => "    umask 027",
          'match'    => '^\s+umask\s+\d+',
          'multiple' => true,
        )
      is_expected.to contain_file_line('login.defs')
        .with(
          'path'  => '/etc/login.defs',
          'line'  => "UMASK           027",
          'match' => '^\s+umask\s+\d+',
        )
      is_expected.to contain_file_line('csh.cshrc')
        .with(
          'path'     => '/etc/csh.cshrc',
          'line'     => "    umask 027",
          'match'    => '^\s+umask\s+\d+',
          'multiple' => true,
        )
    end
  end
end
