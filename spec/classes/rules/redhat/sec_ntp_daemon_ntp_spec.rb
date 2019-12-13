require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_ntp_daemon_ntp' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'ntp_use' => 'unused',
              'ntp' => {
                'chrony_status' => false,
                'ntp_status' => false,
              },
            },
          )
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
              )
            is_expected.to contain_file('/etc/sysconfig/ntpd')
              .with(
                'ensure'  => 'present',
                'owner'   => 'root',
                'group'   => 'root',
                'mode'    => '0644',
                'content' => 'OPTIONS="-u ntp:ntp"',
              )
            is_expected.not_to contain_echo('ntp-daemon')
          else
            is_expected.not_to create_class('ntp')
            is_expected.not_to contain_file('/etc/sysconfig/ntpd')
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
end
