require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_auditd_backlog_limit' do
  on_supported_os.each do |os, _os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          {
            security_baseline: {
              auditd: {
                'backlog_limit' => 'none',
              },
            },
          }
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'set backlog limit',
            'log_level' => 'warning',
            'backlog_limit' => 8192,
          }
        end

        it { is_expected.to compile }
        it {
          if enforce
            is_expected.to contain_kernel_parameter('audit_backlog_limit=8192')
              .with(
                'ensure' => present,
              )
            is_expected.not_to conatin_echo('auditd-backlog-limit')
          else
            is_expected.not_to contain_kernel_parameter('audit_backlog_limit=8192')
            is_expected.to conatin_echo('auditd-backlog-limit')
              .with(
                'message'  => 'set backlog limit',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
