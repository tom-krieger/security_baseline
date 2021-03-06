require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_duplicate_groups' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'srv_avahi' => 'enabled',
            'security_baseline' => {
              'duplicate_groups' => '123456',
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'duplicate groups service',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.not_to contain_echo('duplicate-groups')
          else
            is_expected.to contain_echo('duplicate-groups')
              .with(
                'message'  => 'duplicate groups service',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
