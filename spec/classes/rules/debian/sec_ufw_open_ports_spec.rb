require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_ufw_open_ports' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          security_baseline: {
            services_enabled: {
              srv_ufw: 'disabled',
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'ufw service',
          'log_level' => 'warning',
          'firewall_rules' => {
            'allow ssh' => {
              'queue' => 'in',
              'port' => '22',
              'proto' => 'tcp',
              'action' => 'allow',
            },
            'allow DNS inbound' => {
              'queue' => 'in',
              'port' => '53',
              'proto' => 'udp',
              'action' => 'allow',
            },
          },
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_exec('allow ssh')
            .with(
              'command' => 'ufw allow in 22/tcp',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(ufw status verbose | grep -E -i \'^22/tcp.*ALLOW in\')"',
            )
          is_expected.to contain_exec('allow DNS inbound')
            .with(
              'command' => 'ufw allow in 53/udp',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(ufw status verbose | grep -E -i \'^53/udp.*ALLOW in\')"',
            )
        else
          is_expected.not_to contain_exec('allow ssh')
          is_expected.not_to contain_exec('allow DNS inbound')
        end
      end
    end
  end
end
