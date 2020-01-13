require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_ufw_service' do
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
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_service('ufw')
            .with(
              'ensure' => 'running',
              'enable' => true,
            )
          is_expected.to contain_exec('enable-ufw')
            .with(
              'command' => 'ufw --force enable',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'unless'  => 'test -z "$(ufw status | grep \"Status: inactive\")"',
            )

          is_expected.not_to contain_echo('ufw-service')
        else
          is_expected.not_to contain_service('ufw')
          is_expected.not_to contain_exec('enable-ufw')
          is_expected.to contain_echo('ufw-service')
            .with(
              'message'  => 'ufw service',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
