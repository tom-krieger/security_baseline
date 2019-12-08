require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_network_reverse_path_filtering' do
  enforce_options.each do |enforce|
    on_supported_os.each do |os, os_facts|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'sysctl' => {
                'net.ipv4.conf.all.rp_filter' => '0',
                'net.ipv4.conf.default.rp_filter' => '0',
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'reverse path filtering configuration',
            'log_level' => 'warning',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_sysctl('net.ipv4.conf.all.rp_filter')
              .with(
                'value' => 1,
              )
            is_expected.to contain_sysctl('net.ipv4.conf.default.rp_filter')
              .with(
                'value' => 1,
              )
            is_expected.not_to contain_echo('net.ipv4.conf.all.rp_filter')
          else
            is_expected.not_to contain_sysctl('net.ipv4.conf.all.rp_filter')
            is_expected.not_to contain_sysctl('net.ipv4.conf.default.rp_filter')
            is_expected.to contain_echo('net.ipv4.conf.all.rp_filter')
              .with(
                'message'  => 'reverse path filtering configuration',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
