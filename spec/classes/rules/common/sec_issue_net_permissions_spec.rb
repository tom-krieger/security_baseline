require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_issue_net_permissions' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'issue' => {
                'net' => {
                  'combined' => 666,
                },
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'issue net permissions',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_file('/etc/issue.net')
              .with(
                'ensure' => 'present',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0644',
              )

            is_expected.not_to contain_echo('issue-net-perms')
          else
            is_expected.not_to contain_file('/etc/issue.net')
            is_expected.to contain_echo('issue-net-perms')
              .with(
                'message'  => 'issue net permissions',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
