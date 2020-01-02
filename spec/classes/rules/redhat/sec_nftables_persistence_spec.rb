require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_nftables_persistence' do
  enforce_options.each do |enforce|
    context "RedHat with enforce #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
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
          'message' => 'nftables persistence',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_file('/etc/sysconfig/nftable.conf')
            .with(
              'ensure' => 'present',
              'owner'  => 'root',
              'group'  => 'root',
              'mode'   => '0644',
            )

          is_expected.to contain_file_line('add persistence file include')
            .with(
              'path'               => '/etc/sysconfig/nftables.conf',
              'line'               => 'include "/etc/nftables/nftables.rules"',
              'match'              => 'include "/etc/nftables/nftables.rules"',
              'append_on_no_match' => true,
            )

          is_expected.to contain_exec('dump nftables ruleset')
            .with(
              'command' => 'nft list ruleset > /etc/nftables/nftables.rules',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            )
        else
          is_expected.not_to contain_file('/etc/sysconfig/nftable.conf')
          is_expected.not_to contain_file_line('add persistence file include')
          is_expected.not_to contain_exec('dump nftables ruleset')
        end
      }
    end
  end
end
