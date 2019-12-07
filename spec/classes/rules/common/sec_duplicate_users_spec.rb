require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_duplicate_users' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'srv_avahi' => 'enabled',
            'security_baseline' => {
              'duplicate_users' => '123456',
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'duplicate users service',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.not_to contain_echo('duplicate-users')
          else
            is_expected.to contain_echo('duplicate-users')
              .with(
                'message'  => 'duplicate users service',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
