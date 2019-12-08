require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_passwd_perms' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'file_permissions' => {
                'passwd' => {
                  'combined' => '0-0-777',
                },
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'passwd file permissions',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_file('/etc/passwd')
              .with(
                'ensure' => 'present',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0644',
              )
            is_expected.not_to contain_echo('passwd_perms')
          else
            is_expected.not_to contain_file('/etc/passwd')
            is_expected.to contain_echo('passwd_perms')
              .with(
                'message'  => 'passwd file permissions',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
