require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_network_bogus_icmp_responses' do
  enforce_options.each do |enforce|
    on_supported_os.each do |os, os_facts|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'sysctl' => {
                'net.ipv4.icmp_ignore_bogus_error_responses' => 0,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'bogus icmp response configuration',
            'log_level' => 'warning',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_sysctl('net.ipv4.icmp_ignore_bogus_error_responses')
              .with(
                'value' => 1,
              )

            is_expected.not_to contain_echo('net.ipv4.icmp_ignore_bogus_error_responses')
          else
            is_expected.not_to contain_sysctl('net.ipv4.icmp_ignore_bogus_error_responses')
            is_expected.to contain_echo('net.ipv4.icmp_ignore_bogus_error_responses')
              .with(
                'message'  => 'bogus icmp response configuration',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
