# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::sles::sec_fat' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'kernel_modules' => {
                'vfat' => true,
                'msdos' => false,
                'fat' => false,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'vfat module',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_kmod__install('vfat')
              .with(
                command: '/bin/true',
              )
            is_expected.to contain_kmod__install('fat')
              .with(
                command: '/bin/true',
              )
            is_expected.to contain_kmod__install('msdos')
              .with(
                command: '/bin/true',
              )
            is_expected.not_to contain_echo('vfat-kernel-modules')
          else
            is_expected.not_to contain_kmod__install('vfat')
            is_expected.not_to contain_kmod__install('fat')
            is_expected.not_to contain_kmod__install('msdos')
            is_expected.to contain_echo('vfat-kernel-modules')
              .with(
                'message'  => 'vfat module',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
