require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_network_tcp_syn_cookies' do
  enforce_options.each do |enforce|
    on_supported_os.each do |os, os_facts|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'sysctl' => {
                'net.ipv4.tcp_syncookies' => 0,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'tcp syn cookies configuration',
            'log_level' => 'warning',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_sysctl('net.ipv4.tcp_syncookies')
              .with(
                'value' => 1,
              )

            is_expected.not_to contain_echo('net.ipv4.tcp_syncookies')
          else
            is_expected.not_to contain_sysctl('net.ipv4.tcp_syncookies')
            is_expected.to contain_echo('net.ipv4.tcp_syncookies')
              .with(
                'message'  => 'tcp syn cookies configuration',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
