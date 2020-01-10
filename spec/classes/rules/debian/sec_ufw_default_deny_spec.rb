require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_ufw_default_deny' do
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
            ufw: {
              default_deny_status: false,
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'ufw default deny',
          'log_level' => 'warning',
          'default_incoming' => 'deny',
          'default_outgoing' => 'deny',
          'default_routed' => 'deny',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_exec('default incoming policy deny')
            .with(
              'command' => 'ufw default deny incoming',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => "test -z \"$(ufw status verbose | grep 'deny (incoming)')\"",
            )

          is_expected.to contain_exec('default outgoing policy deny')
            .with(
              'command' => 'ufw default deny outgoing',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => "test -z \"$(ufw status verbose | grep 'deny (outgoing  )')\"",
            )

          is_expected.to contain_exec('default routed policy deny')
            .with(
              'command' => 'ufw default deny routed',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => "test -z \"$(ufw status verbose | grep 'deny (routed)')\"",
            )

          is_expected.not_to contain_echo('ufw-default-deny')
        else
          is_expected.not_to contain_exec('default incoming policy deny')
          is_expected.not_to contain_exec('default outgoing policy deny')
          is_expected.not_to contain_exec('default routed policy deny')
          is_expected.to contain_echo('ufw-default-deny')
            .with(
              'message'  => 'ufw default deny',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
