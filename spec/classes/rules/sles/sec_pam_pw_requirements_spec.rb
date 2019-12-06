require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::sles::sec_pam_pw_requirements' do
  enforce_options.each do |enforce|
    context "Suse with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Suse',
          operatingsystem: 'SLES',
          architecture: 'x86_64',
          security_baseline: {
            pam: {
              pwquality: {
                status: false,
              },
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'pam password requirements',
          'log_level' => 'warning',
          'minlen' => 14,
          'dcredit' => -1,
          'ucredit' => -1,
          'lcredit' => -1,
          'ocredit' => -1,
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_package('libpwquality1')
            .with(
              'ensure' => 'installed',
            )
          is_expected.to contain_file_line('pam minlen')
            .with(
              'ensure' => 'present',
              'path'   => '/etc/security/pwquality.conf',
              'line'   => 'minlen = 14',
              'match'  => '^#?minlen',
            )

          is_expected.to contain_file_line('pam dcredit')
            .with(
              'ensure' => 'present',
              'path'   => '/etc/security/pwquality.conf',
              'line'   => 'dcredit = -1',
              'match'  => '^#?dcredit',
            )

          is_expected.to contain_file_line('pam ucredit')
            .with(
              'ensure' => 'present',
              'path'   => '/etc/security/pwquality.conf',
              'line'   => 'ucredit = -1',
              'match'  => '^#?ucredit',
            )

          is_expected.to contain_file_line('pam ocredit')
            .with(
              'ensure' => 'present',
              'path'   => '/etc/security/pwquality.conf',
              'line'   => 'ocredit = -1',
              'match'  => '^#?ocredit',
            )

          is_expected.to contain_file_line('pam lcredit')
            .with(
              'ensure' => 'present',
              'path'   => '/etc/security/pwquality.conf',
              'line'   => 'lcredit = -1',
              'match'  => '^#?lcredit',
            )

          is_expected.to contain_pam('pam_cracklib common-password')
            .with(
              'ensure'    => 'present',
              'service'   => 'common-password',
              'type'      => 'password',
              'control'   => 'requisite',
              'module'    => 'pam_cracklib.so',
              'arguments' => [
                'try_first_pass',
                'retry=3',
                'minlen=14',
                'dcredit=-1',
                'ucredit=-1',
                'ocredit=-1',
                'lcredit=-1',
              ],
            )

          is_expected.not_to contain_echo('pam-password-complexity')
        else
          is_expected.not_to contain_package('libpwquality1')
          is_expected.not_to contain_file_line('pam minlen')
          is_expected.not_to contain_file_line('pam ucredit')
          is_expected.not_to contain_file_line('pam ocredit')
          is_expected.not_to contain_file_line('pam lcredit')
          is_expected.not_to contain_pam('pam_cracklib common-password')
          is_expected.to contain_echo('pam-password-complexity')
            .with(
              'message'  => 'pam password requirements',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
