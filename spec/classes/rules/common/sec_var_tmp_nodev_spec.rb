require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_var_tmp_nodev' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'mountpoints' => {
              '/var/tmp' => {
                'options' => ['rw'],
              },
            },
            'security_baseline' => {
              'partitions' => {
                'var_tmp' => {
                  'nodev' => false,
                  'noexec' => false,
                  'nosuid' => false,
                  'partition' => '/var/tmp',
                },
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'var_tmp nodev',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_security_baseline__set_mount_options('/var/tmp-nodev')
              .with(
                'mountpoint'   => '/var/tmp',
                'mountoptions' => 'nodev',
              )

            is_expected.not_to contain_echo('var-tmp-nodev')
          else
            is_expected.not_to contain_security_baseline__set_mount_options('/var/tmp-nodev')
            is_expected.to contain_echo('var-tmp-nodev')
              .with(
                'message'  => 'var_tmp nodev',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
