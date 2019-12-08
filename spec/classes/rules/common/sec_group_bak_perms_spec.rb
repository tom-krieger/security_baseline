require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_group_bak_perms' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'file_permissions' => {
                'group-' => {
                  'combined' => '0-0-777',
                },
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'group bak file permissions',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_file('/etc/group-')
              .with(
                'ensure' => 'present',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0644',
              )
            is_expected.not_to contain_echo('group_bak_perms')
          else
            is_expected.not_to contain_file('/etc/group-')
            is_expected.to contain_echo('group_bak_perms')
              .with(
                'message'  => 'group bak file permissions',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
