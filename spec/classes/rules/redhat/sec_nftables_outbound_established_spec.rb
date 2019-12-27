require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_nftables_outbound_established' do
  enforce_options.each do |enforce|
    context "RedHat with enforce #{enforce}" do
      let(:pre_condition) do
        <<-EOF
        exec { 'dump nftables ruleset':
          command     => 'nft list ruleset > /etc/nftables/nftables.rules',
          path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          refreshonly => true,
        }
        EOF
      end
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
              'table_count' => 0,
              'table_count_status' => false,
              'base_chain_status' => false,
              'conns' => {
                'status' => false,
                'in_tcp' => false,
                'in_udp' => false,
                'in_icmp' => false,
                'out_tcp' => false,
                'out_udp' => false,
                'out_icmp' => false,
              },
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'nftables base chains',
          'log_level' => 'warning',
          'table' => 'inet',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_exec('add nftables rule for input tcp established')
            .with(
              'command' => 'nft add rule inet filter input ip protocol tcp ct state established accept',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(nft list ruleset | grep \'ip protocol tcp ct state established accept\')"',
            )
            .that_notifies('Exec[dump nftables ruleset]')

          is_expected.to contain_exec('add nftables rule for input udp established')
            .with(
              'command' => 'nft add rule inet filter input ip protocol udp ct state established accept',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(nft list ruleset | grep \'ip protocol udp ct state established accept\')"',
            )
            .that_notifies('Exec[dump nftables ruleset]')

          is_expected.to contain_exec('add nftables rule for input icmp established')
            .with(
              'command' => 'nft add rule inet filter input ip protocol icmp ct state established accept',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(nft list ruleset | grep \'ip protocol icmp ct state established accept\')"',
            )
            .that_notifies('Exec[dump nftables ruleset]')

          is_expected.to contain_exec('add nftables rule for output tcp established')
            .with(
              'command' => 'nft add rule inet filter output ip protocol tcp ct state new,related,established accept',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(nft list ruleset | grep \'ip protocol tcp ct state new,related,established accept\')"',
            )
            .that_notifies('Exec[dump nftables ruleset]')

          is_expected.to contain_exec('add nftables rule for output udp established')
            .with(
              'command' => 'nft add rule inet filter output ip protocol udp ct state new,related,established accept',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(nft list ruleset | grep \'ip protocol udp ct state new,related,established accept\')"',
            )
            .that_notifies('Exec[dump nftables ruleset]')

          is_expected.to contain_exec('add nftables rule for output icmp established')
            .with(
              'command' => 'nft add rule inet filter output ip protocol icmp ct state new,related,established accept',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(nft list ruleset | grep \'ip protocol icmp ct state new,related,established accept\')"',
            )
            .that_notifies('Exec[dump nftables ruleset]')

          is_expected.not_to contain_echo('nftables-outbound-established')
        else
          is_expected.not_to contain_exec('add nftables rule for input tcp established')
          is_expected.not_to contain_exec('add nftables rule for input udp established')
          is_expected.not_to contain_exec('add nftables rule for input icmp established')
          is_expected.not_to contain_exec('add nftables rule for output tcp established')
          is_expected.not_to contain_exec('add nftables rule for output udp established')
          is_expected.not_to contain_exec('add nftables rule for output icmp established')
          is_expected.to contain_echo('nftables-outbound-established')
            .with(
              'message'  => 'nftables base chains',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
