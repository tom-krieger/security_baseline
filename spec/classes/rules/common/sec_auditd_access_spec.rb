require 'spec_helper'

enforce_options = [true, false]
arch_options = ['x86_64', 'i686']

describe 'security_baseline::rules::common::sec_auditd_access' do

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
            EOF
          }
          let(:facts) { {
            :osfamily => 'RedHat',
            :operatingsystem => 'CentOS',
            :architecture => "#{arch}",
            :security_baseline => {
              :auditd => {
                :access => false
              }
            }
          } }
          let(:params) do
            {
              'enforce' => enforce,
              'message' => 'sec_auditd_access test',
              'log_level' => 'warning',
            }
          end

          it { is_expected.to compile }
          
          if enforce
            it {
              is_expected.to contain_file_line('watch access rule 1')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/audit/rules.d/sec_baseline_auditd.rules',
                  'line'   => '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access',
                )
              is_expected.to contain_file_line('watch access rule 2')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/audit/rules.d/sec_baseline_auditd.rules',
                  'line'   => '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access',
                )

              if arch == 'x86_64'
                is_expected.to contain_file_line('watch access rule 3')
                  .with(
                    'ensure' => 'present',
                    'path'   => '/etc/audit/rules.d/sec_baseline_auditd.rules',
                    'line'   => '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access',
                  )
                is_expected.to contain_file_line('watch access rule 4')
                  .with(
                    'ensure' => 'present',
                    'path'   => '/etc/audit/rules.d/sec_baseline_auditd.rules',
                    'line'   => '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access',
                  )
              end
            }
            
          else
            it { 
              is_expected.to contain_echo('auditd-access')
                .with(
                  'message'  => 'Auditd has no rule to collect unsuccessful unauthorized file access attempts.',
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
