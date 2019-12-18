require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_audit_suid_programs' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline_suid_programs' => ['/usr/sbin/postdrop', '/usr/sbin/netreport'],
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'Audit suid programs',
            'log_level' => 'warning',
            'suid_expected' => ['/usr/sbin/postdrop'],
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.not_to contain_echo('suid-programs')
            is_expected.to contain_echo('unexpected-suid-program-/usr/sbin/netreport')
              .with(
                'message'  => 'unexpected suid program /usr/sbin/netreport',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          else
            is_expected.not_to contain_echo('unexpected-suid-program-/usr/sbin/netreport')
            is_expected.to contain_echo('suid-programs')
              .with(
                'message'  => 'Audit suid programs',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
