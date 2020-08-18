require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_sudo_package' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'packages_installed' => {
                'sudo' => false,
              },
              'sudo' => {
                'use_pty' => 'none',
                'logfile' => 'none',
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'sudo package',
            'log_level' => 'warning',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_package('sudo')
              .with(
                'ensure' => 'present',
              )

            is_expected.not_to contain_echo('sudo-package')
          else
            is_expected.not_to contain_package('sudo')
            is_expected.to contain_echo('sudo-package')
              .with(
                'message'  => 'sudo package',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
