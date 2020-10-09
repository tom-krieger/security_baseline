require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_auditd_service' do
  enforce_options.each do |enforce|
    context "on RedHat 7 with enforce = #{enforce}" do
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
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          operatingsystemmajrelease: '7',
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
          is_expected.to contain_package('audit').with('ensure' => 'present')
          is_expected.to contain_service('auditd')
            .with(
              'ensure'  => 'running',
              'enable'  => true,
            )

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

    context "on RedHat 8 with enforce = #{enforce}" do
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
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          operatingsystemmajrelease: '8',
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
        is_expected.not_to contain_package('audit')
        if enforce
          is_expected.to contain_service('auditd')
            .with(
              'ensure'  => 'running',
              'enable'  => true,
            )

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
