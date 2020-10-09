require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_auditd_service' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce}" do
      let(:pre_condition) do
        <<-EOF
        class { 'security_baseline':
          baseline_version => '1.0.0',
          rules => {},
          logfile => '/opt/puppetlabs/facter/facts.d/security_baseline_findings.yaml',
          auditd_rules_file => '/etc/audit/rules.d/sec_baseline_auditd.rules',
        }

        exec { 'reload auditd rules':
          refreshonly => true,
          command     => "auditctl -R ${security_baseline::auditd_rules_file}",
          path        => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
        }
        EOF
      end
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          security_baseline: {
            auditd: {
              srv_auditd: false,
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'sec_auditd_service test',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it {
        if enforce
          is_expected.to contain_package('auditd').with('ensure' => 'present')
          is_expected.to contain_service('auditd')
            .with(
              'ensure'  => 'running',
              'enable'  => true,
            )
            .that_requires('Package[auditd]')

          is_expected.not_to contain_echo('auditd-service')
        else
          is_expected.to contain_echo('auditd-service')
            .with(
              'message'  => 'Auditd servive should be enabled and running.',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
