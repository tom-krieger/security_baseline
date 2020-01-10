require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_nftables_base_chains' do
  enforce_options.each do |enforce|
    context "Debian with enforce #{enforce}" do
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
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          'security_baseline' => {
            'nftables' => {
              'base_chain_input' => 'none',
              'base_chain_forward' => 'none',
              'base_chain_output' => 'none',
              'table_count' => 0,
              'table_count_status' => false,
              'base_chain_status' => false,
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
          is_expected.to contain_exec('create base chain input')
            .with(
              'command' => 'nft create chain inet filter input { type filter hook input priority 0 \; }',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(nft list ruleset inet | grep \'type filter hook input priority 0\')"',
            )
            .that_notifies('Exec[dump nftables ruleset]')

          is_expected.to contain_exec('create base chain forward')
            .with(
              'command' => 'nft create chain inet filter forward { type filter hook forward priority 0 \; }',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(nft list ruleset inet | grep \'type filter hook forward priority 0\')"',
            )
            .that_notifies('Exec[dump nftables ruleset]')

          is_expected.to contain_exec('create base chain output')
            .with(
              'command' => 'nft create chain inet filter output { type filter hook output priority 0 \; }',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(nft list ruleset inet | grep \'type filter hook output priority 0\')"',

            )
            .that_notifies('Exec[dump nftables ruleset]')

          is_expected.not_to contain_echo('nftables-base-chains')
        else
          is_expected.not_to contain_exec('create base chain input')
          is_expected.not_to contain_exec('create base chain forward')
          is_expected.not_to contain_exec('create base chain output')
          is_expected.to contain_echo('nftables-base-chains')
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
