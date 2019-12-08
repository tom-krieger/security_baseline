require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_iptables' do
  enforce_options.each do |enforce|
    on_supported_os.each do |os, os_facts|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'packages_installed' => {
                'iptables' => false,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'iptables package',
            'log_level' => 'warning',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_package('iptables')
              .with(
                'ensure' => 'installed',
              )

            is_expected.not_to contain_echo('iptables')
          else
            is_expected.not_to contain_package('iptables')
            is_expected.to contain_echo('iptables')
              .with(
                'message'  => 'iptables package',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
