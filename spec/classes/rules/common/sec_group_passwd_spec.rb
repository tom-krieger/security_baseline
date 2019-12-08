require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_group_passwd' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'passwd_group' => 'xyz-123',
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'group passwd test',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.not_to contain_echo('group-passwd-test')
          else
            is_expected.to contain_echo('group-passwd-test')
              .with(
                'message'  => 'group passwd test',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
