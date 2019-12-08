require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_nfs_rpcbind' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'services_enabled' => {
                'srv_nfs' => 'enabled',
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'nfs service',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_service('nfs')
              .with(
                'ensure' => 'stopped',
                'enable' => false,
              )
            is_expected.to contain_service('nfs-server')
              .with(
                'ensure' => 'stopped',
                'enable' => false,
              )
            is_expected.to contain_service('rpcbind')
              .with(
                'ensure' => 'stopped',
                'enable' => false,
              )
            is_expected.not_to contain_echo('nfs')
          else
            is_expected.not_to contain_service('nfs')
            is_expected.not_to contain_service('nfs-server')
            is_expected.not_to contain_service('rpcbind')
            is_expected.to contain_echo('nfs')
              .with(
                'message'  => 'nfs service',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
