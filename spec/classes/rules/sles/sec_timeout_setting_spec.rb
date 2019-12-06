require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::sles::sec_timeout_setting' do

  enforce_options.each do |enforce|

    context "Suse with enforce = #{enforce}" do
      let(:facts) { {
        :osfamily => 'Suse',
        :operatingsystem => 'SLES',
        :architecture => 'x86_64',
        :security_baseline => {
          :timeout => true,
        }
      } }
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'timeout setting',
          'log_level' => 'warning',
          'default_timeout' => 900,
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
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

          is_expected.not_to contain_echo('timeout-setting')
        else
          is_expected.not_to contain_file_line('bashrc_tmout')
          is_expected.not_to contain_file_line('profile_tmout')
          is_expected.to contain_echo('timeout-setting')
            .with(
              'message'  => 'timeout setting',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
