require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_nftables_loopback' do
  enforce_options.each do |enforce|
    context "RedHat with enforce #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          'security_baseline' => {
            'nftables' => {
              'base_chain_input' => 'none',
              'base_chain_forward' => 'none',
              'base_chain_output' => 'none',
              'base_chain_status' => false,
              'table_count' => 0,
              'table_count_status' => false,
              'loopback' => {
                'lo_iface' => 'none',
                'lo_network' => 'none',
                'ip6_saddr' => 'none',
                'status' => false,
              },
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'nftables loopback',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_exec('nftables add local interface')
            .with(
              'command' => 'nft add rule inet filter input iif lo accept',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            )

          is_expected.to contain_exec('nftables add local network')
            .with(
              'command' => 'nft create rule inet filter input ip saddr 127.0.0.0/8 counter drop',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            )

          is_expected.to contain_exec('nftables ip6 traffic')
            .with(
              'command' => 'nft add rule inet filter input ip6 saddr ::1 counter drop',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            )
          is_expected.not_to contain_echo('nftables-loopback')
        else
          is_expected.not_to contain_exec('nftables add local interface')
          is_expected.not_to contain_exec('nftables add local network')
          is_expected.not_to contain_exec('nftables ip6 traffic')
          is_expected.to contain_echo('nftables-loopback')
            .with(
              'message'  => 'nftables loopback',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
