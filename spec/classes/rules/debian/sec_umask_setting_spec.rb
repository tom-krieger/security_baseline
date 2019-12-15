require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_umask_setting' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          security_baseline: {
            umask: true,
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'umask setting',
          'log_level' => 'warning',
          'default_umask' => '027',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_file_line('bashrc')
            .with(
              'path'     => '/etc/bash.bashrc',
              'line'     => '      umask 027',
              'match'    => '^\s+umask\s+\d+',
              'multiple' => true,
            )
          is_expected.to contain_file_line('profile')
            .with(
              'path'     => '/etc/profile',
              'line'     => '    umask 027',
              'match'    => '^\s+umask\s+\d+',
              'multiple' => true,
            )
          is_expected.to contain_file_line('login.defs')
            .with(
              'path'  => '/etc/login.defs',
              'line'  => 'UMASK           027',
              'match' => '^\s+umask\s+\d+',
            )

          is_expected.not_to contain_echo('umask-setting')
        else
          is_expected.not_to contain_file_line('bashrc')
          is_expected.not_to contain_file_line('profile')
          is_expected.not_to contain_file_line('login.defs')
          is_expected.to contain_echo('umask-setting')
            .with(
              'message'  => 'umask setting',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
