require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::sles::sec_pam_old_passwords' do

  enforce_options.each do |enforce|

    context "Suse with enforce = #{enforce}" do
      let(:facts) { {
        :osfamily => 'Suse',
        :operatingsystem => 'SLES',
        :architecture => 'x86_64',
        :security_baseline => {
          :pam => {
            :opasswd => {
              :status => false,
            }
          }
        }
      } }
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'pam old passwords',
          'log_level' => 'warning',
          'oldpasswords' => 5,
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
        is_expected.to contain_pam('pam-common-pw-history')
          .with(
            'ensure'    => 'present',
            'service'   => 'common-password',
            'type'      => 'password',
            'control'   => 'required',
            'module'    => 'pam_pwhistory.so',
            'arguments' => ["remember=5"],
          )

        is_expected.not_to contain_echo('password-reuse')
        else
          is_expected.not_to contain_pam('pam-common-pw-history')
          is_expected.to contain_echo('password-reuse')
            .with(
              'message'  => 'pam old passwords',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
