require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_wlan_interfaces' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          security_baseline: {
            umask: true,
          },
          'security_baseline' => {
            'wlan_interfaces_count' => 1,
            'wlan_interfaces' => ['wlan1'],
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'wlan interfaces',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_exec('shutdown wlan interface wlan1')
            .with(
              'command' => 'ip link set wlan1 down',
              'path'    => ['/bin', '/sbin', '/usr/bin', '/usr/sbin'],
              'onlyif'  => "ip link show wlan1 | grep 'state UP'",
            )
          is_expected.not_to contain_echo('wlan-interfaces')
        else
          is_expected.not_to contain_service('shutdown wlan interface wlan1')
          is_expected.to contain_echo('wlan-interfaces')
            .with(
              'message'  => 'wlan interfaces',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
