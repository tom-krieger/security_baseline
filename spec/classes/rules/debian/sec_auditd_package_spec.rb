require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_auditd_package' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          operatingsystemmajrelease: 7,
          architecture: 'x86_64',
          security_baseline: {
            auditd: {
              srv_auditd: false,
            },
            'packages_installed' => {
              'auditd' => true,
              'audispd-plugins' => false,
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'auditd packages',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it {
        if enforce
          is_expected.to contain_package('audispd-plugins').with('ensure' => 'installed')
          is_expected.not_to contain_echo('auditd-packages')
          is_expected.to contain_package('auditd').with('ensure' => 'installed')
        else
          is_expected.not_to contain_package('audispd-plugins')
          is_expected.not_to contain_package('auditd')
          is_expected.to contain_echo('auditd-packages')
            .with(
              'message'  => 'auditd packages',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
