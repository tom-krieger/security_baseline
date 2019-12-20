require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_firewalld_iptables_service' do
  enforce_options.each do |enforce|
    context "RedHat with enforce #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          'security_baseline' => {
            'services_enabled' => {
              'srv_iptables' => true,
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'firewalld iptables service',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_service('iptables')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )
          is_expected.not_to contain_echo('firewalld-iptables-service')
        else
          is_expected.not_to contain_service('iptables')
          is_expected.to contain_echo('firewalld-iptables-service')
            .with(
              'message'  => 'firewalld iptables service',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
