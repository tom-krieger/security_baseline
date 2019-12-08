require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_network_secure_icmp_redirect' do
  enforce_options.each do |enforce|
    on_supported_os.each do |os, os_facts|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'sysctl' => {
                'net.ipv4.conf.all.secure_redirects' => '1',
                'net.ipv4.conf.default.secure_redirects' => '1',
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'secure icmp redirect packets configuration',
            'log_level' => 'warning',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_sysctl('net.ipv4.conf.all.secure_redirects')
              .with(
                'value' => 0,
              )
            is_expected.to contain_sysctl('net.ipv4.conf.default.secure_redirects')
              .with(
                'value' => 0,
              )
            is_expected.not_to contain_echo('net.ipv4.conf.all.secure_redirects')
          else
            is_expected.not_to contain_sysctl('net.ipv4.conf.all.secure_redirects')
            is_expected.not_to contain_sysctl('net.ipv4.conf.default.secure_redirects')
            is_expected.to contain_echo('net.ipv4.conf.all.secure_redirects')
              .with(
                'message'  => 'secure icmp redirect packets configuration',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
