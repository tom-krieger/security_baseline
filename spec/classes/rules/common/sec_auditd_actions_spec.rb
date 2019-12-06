require 'spec_helper'

enforce_options = [true, false]
arch_options = ['x86_64', 'i686']

describe 'security_baseline::rules::common::sec_auditd_actions' do

  on_supported_os.each do |os, os_facts|

    enforce_options.each do |enforce|

      arch_options.each do |arch|

        context "on #{os} with enforce = #{enforce} and arch = #{arch}" do
          let(:pre_condition) { <<-EOF
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
          }
          let(:facts) { {
            :architecture => "#{arch}",
            :security_baseline => {
              :auditd => {
                :actions => false
              }
            }
          } }
          let(:params) do
            {
              'enforce' => enforce,
              'message' => 'sec_auditd_actions test',
              'log_level' => 'warning',
            }
          end

          it { is_expected.to compile }
          
          if enforce
            it {
              is_expected.to contain_file_line('watch admin actions rule 1')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/audit/rules.d/sec_baseline_auditd.rules',
                  'line'   => '-w /var/log/sudo.log -p wa -k actions',
                )
                .that_notifies('Exec[reload auditd rules]')
            }
            
          else
            it { 
              is_expected.to contain_echo('auditd-actions')
                .with(
                  'message'  => 'Auditd has no rule to collect system administrator actions (sudolog).',
                  'loglevel' => 'warning',
                  'withpath' => false,
                )
            }
          end
        end
      end

    end
  end
  
end
