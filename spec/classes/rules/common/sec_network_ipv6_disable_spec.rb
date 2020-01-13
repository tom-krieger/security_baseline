require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_network_ipv6_disable' do
  enforce_options.each do |enforce|
    on_supported_os.each do |os, os_facts|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'grub_ipv6_disabled' => false,
              'sysctl' => {
                'net.ipv6.conf.all.disable_ipv6' => 0,
                'net.ipv6.conf.default.disable_ipv6' => 0,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'ipv6 disable configuration',
            'log_level' => 'warning',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_sysctl('net.ipv6.conf.all.disable_ipv6')
              .with(
                'value' => 1,
              )
            is_expected.to contain_sysctl('net.ipv6.conf.default.disable_ipv6')
              .with(
                'value' => 1,
              )
            is_expected.not_to contain_echo('net.ipv6.conf.all.disable_ipv6')
          else
            is_expected.not_to contain_sysctl('net.ipv6.conf.all.disable_ipv6')
            is_expected.not_to contain_sysctl('net.ipv6.conf.default.disable_ipv6')
            is_expected.to contain_echo('net.ipv6.conf.all.disable_ipv6')
              .with(
                'message'  => 'ipv6 disable configuration',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
