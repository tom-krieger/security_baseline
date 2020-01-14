require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_ldap' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'srv_avahi' => 'enabled',
            'security_baseline' => {
              'services_enabled' => {
                'srv_slapd' => 'enabled',
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'ldap service',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_service('slapd')
              .with(
                'ensure' => 'stopped',
                'enable' => false,
              )
            is_expected.not_to contain_echo('ldap')
          else
            is_expected.not_to contain_service('slapd')
            is_expected.to contain_echo('ldap')
              .with(
                'message'  => 'ldap service',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
