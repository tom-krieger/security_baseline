require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_ntp_daemon_ntp' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce}" do
      let(:facts) do
        {
          'osfamily' => 'Debian',
          'operatingsystem' => 'Ubuntu',
          'architecture' => 'x86_64',
          'security_baseline' => {
            'ntp_use' => 'unused',
            'ntp' => {
              'chrony_status' => false,
              'ntp_status' => false,
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'ntp class',
          'log_level' => 'warning',
          'ntp_servers' => ['10.10.10.1', '10.10.10.2'],
          'ntp_statsdir' => '/var/tmp',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to create_class('ntp')
            .with(
              'servers' => ['10.10.10.1', '10.10.10.2'],
              'restrict'        => [],
              'statsdir'        => '/var/tmp',
              'disable_monitor' => true,
              'iburst_enable'   => false,
              'service_manage'  => false,
            )

          is_expected.to contain_file_line('ntp runas user')
            .with(
              'line'  => 'RUNASUSER=ntp',
              'path'  => '/etc/init.d/ntp',
              'match' => '^RUNASUSER',
            )

          is_expected.not_to contain_echo('ntp-daemon')
        else
          is_expected.not_to create_class('ntp')
          is_expected.not_to contain_file_line('ntp runas user')
          is_expected.to contain_echo('ntp-daemon')
            .with(
              'message'  => 'ntp class',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
