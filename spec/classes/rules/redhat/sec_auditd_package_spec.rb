require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_auditd_package' do
  enforce_options.each do |enforce|
    context "on RedHat with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          operatingsystemmajrelease: 7,
          architecture: 'x86_64',
          security_baseline: {
            auditd: {
              srv_auditd: false,
            },
            'packages_installed' => {
              'audit' => true,
              'audit-libs' => false,
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
          is_expected.to contain_package('audit-libs').with('ensure' => 'present')
          is_expected.not_to contain_echo('auditd-packages')
          is_expected.to contain_package('audit').with('ensure' => 'present')
        else
          is_expected.not_to contain_package('audit-libs')
          is_expected.not_to contain_package('audit')
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
