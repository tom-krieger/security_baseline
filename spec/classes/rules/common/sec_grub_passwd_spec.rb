require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_grub_passwd' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'grub' => {
                'grub_passwd' => false,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'grub password',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_echo('grub-passwd')
              .with(
                'message'  => 'grub password',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          else
            is_expected.not_to contain_echo('grub-passwd')
          end
        }
      end
    end
  end
end
