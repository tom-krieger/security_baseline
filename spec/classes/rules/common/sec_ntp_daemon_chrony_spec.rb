require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_ntp_daemon_chrony' do
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
            'message' => 'chrony class',
            'log_level' => 'warning',
            'ntp_servers' => [
              { 'hostname' => '10.10.10.1' },
              { 'hostname' => '10.10.10.2' },
            ],
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to create_class('chrony')
              .with(
                'servers' => [
                  { 'hostname' => '10.10.10.1' },
                  { 'hostname' => '10.10.10.2' },
                ],
              )
            is_expected.not_to contain_echo('chrony-daemon')
          else
            is_expected.not_to create_class('chrony')
            is_expected.to contain_echo('chrony-daemon')
              .with(
                'message'  => 'chrony class',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
