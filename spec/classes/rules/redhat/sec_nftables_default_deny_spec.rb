require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_nftables_default_deny' do
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
              'conns' => {
                'status' => false,
                'in_tcp' => false,
                'in_udp' => false,
                'in_icmp' => false,
                'out_tcp' => false,
                'out_udp' => false,
                'out_icmp' => false,
              },
              'policy' => {
                'input' => 'accept',
                'forward' => 'accept',
                'output' => 'accept',
                'status' => false,
              },
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'nftables default deny',
          'log_level' => 'warning',
          'default_policy_input' => 'drop',
          'default_policy_forward' => 'drop',
          'default_policy_output' => 'drop',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_exec('set input default policy')
            .with(
              'command' => 'nft chain inet filter input { policy drop ; }',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            )

          is_expected.to contain_exec('set forward default policy')
            .with(
              'command' => 'nft chain inet filter forward { policy drop ; }',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            )

          is_expected.to contain_exec('set output default policy')
            .with(
              'command' => 'nft chain inet filter output { policy drop ; }',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            )

          is_expected.not_to contain_echo('nftables-default-deny')
        else
          is_expected.not_to contain_exec('set input default policy')
          is_expected.not_to contain_exec('set forward default policy')
          is_expected.not_to contain_exec('set output default policy')
          is_expected.to contain_echo('nftables-default-deny')
            .with(
              'message'  => 'nftables default deny',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
