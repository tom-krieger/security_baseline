require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_ufw_outbound' do
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
            'allow DNS outbound' => {
              'queue' => 'out',
              'to' => 'any',
              'port' => '53',
              'proto' => 'udp',
              'action' => 'allow',
            },
            'allow http outbound' => {
              'queue' => 'out',
              'to' => 'any',
              'port' => '80',
              'proto' => 'tcp',
              'action' => 'allow',
            },
          },
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_exec('allow DNS outbound')
            .with(
              'command' => 'ufw allow out to any port 53',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(ufw status verbose | grep -E -i \'^53.*ALLOW out\')"',
            )
          is_expected.to contain_exec('allow http outbound')
            .with(
              'command' => 'ufw allow out to any port 80',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(ufw status verbose | grep -E -i \'^80.*ALLOW out\')"',
            )
        else
          is_expected.not_to contain_exec('allow DNS outbound')
          is_expected.not_to contain_exec('allow http outbound')
        end
      end
    end
  end
end
