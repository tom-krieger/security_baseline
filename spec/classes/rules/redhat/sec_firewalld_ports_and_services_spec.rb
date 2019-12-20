require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_firewalld_ports_and_services' do
  enforce_options.each do |enforce|
    context "RedHat with enforce #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          'security_baseline' => {
            'firewalld' => {
              'ports' => ['23/tcp'],
              'services' => ['cockpit', 'dhcpv6-client', 'ssh'],
              'ports_and_services_status' => true,
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'firewalld ports and services',
          'log_level' => 'warning',
          'expected_ports' => ['25/tcp'],
          'expected_services' => ['ssh'],
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_exec('firewalld remove port 23/tcp')
            .with(
              'command' => 'firewall-cmd --remove-port=23/tcp',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            )

          is_expected.to contain_exec('firewalld remove service cockpit')
            .with(
              'command' => 'firewall-cmd --remove-service=cockpit',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            )

          is_expected.to contain_exec('firewalld remove service dhcpv6-client')
            .with(
              'command' => 'firewall-cmd --remove-service=dhcpv6-client',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            )

          is_expected.not_to contain_echo('firewalld-services-ports')
        else
          is_expected.not_to contain_exec('firewalld remove port 23/tcp')
          is_expected.not_to contain_exec('firewalld remove service cockpit')
          is_expected.not_to contain_exec('firewalld remove service dhcpv6-client')
          is_expected.to contain_echo('firewalld-services-ports')
            .with(
              'message'  => 'firewalld ports and services',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
