require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_firewalld_iface_assignment' do
  enforce_options.each do |enforce|
    context "RedHat with enforce #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          'security_baseline' => {
            'firewalld' => {
              'default_zone_status' => false,
              'zone_iface_assigned_status' => false,
              'zone_iface' => {
                'public' => 'eth1',
              },
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'firewalld interface zone',
          'log_level' => 'warning',
          'zone_config' => {
            'public' => 'eth0',
          },
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_exec('firewalld change zone interface')
            .with(
              'command' => 'firewall-cmd --zone=public --change-interface=eth0',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            )

          is_expected.not_to contain_echo('firewalld-iface-assignment')
        else
          is_expected.not_to contain_exec('firewalld change zone interface')
          is_expected.to contain_echo('firewalld-iface-assignment')
            .with(
              'message'  => 'firewalld interface zone',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
