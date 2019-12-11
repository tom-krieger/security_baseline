require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_kernel_aslr' do
  enforce_options.each do |enforce|
    on_supported_os.each do |os, os_facts|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'sysctl' => {
                'kernel.randomize_va_space' => 1,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'kernel aslr',
            'log_level' => 'warning',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_sysctl('kernel.randomize_va_space')
              .with(
                'value' => 2,
              )

            is_expected.not_to contain_echo('kernel-aslr')
          else
            is_expected.not_to contain_sysctl('kernel.randomize_va_space')
            is_expected.to contain_echo('kernel-aslr')
              .with(
                'message'  => 'kernel aslr',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
