require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_nftables_service' do
  enforce_options.each do |enforce|
    context "Debian with enforce #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          'security_baseline' => {
            'services_enabled' => {
              'srv_nftables' => false,
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'nftables service',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_service('nftables')
            .with(
              'ensure' => 'running',
              'enable' => true,
            )
          is_expected.not_to contain_echo('nftables-service')
        else
          is_expected.not_to contain_service('nftables')
          is_expected.to contain_echo('nftables-service')
            .with(
              'message'  => 'nftables service',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
