require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::sles::sec_apparmor_bootloader' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:pre_condition) do
          <<-EOF
          exec {'apparmor-grub-config':
            command     => 'grub2-mkconfig -o /boot/grub2/grub.cfg',
            path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            refreshonly => true,
          }
          EOF
        end
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'apparmor' => {
                'bootloader' => false,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'bootloader apparmor',
            'log_level' => 'warning',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_file_line('cmdline_definition')
              .with(
                'line'  => 'GRUB_CMDLINE_LINUX_DEFAULT="quiet"',
                'path'  => '/etc/default/grub',
                'match' => '^GRUB_CMDLINE_LINUX_DEFAULT',
              )
              .that_notifies('Exec[apparmor-grub-config]')

            is_expected.not_to contain_echo('bootloader-apparmor')
          else
            is_expected.not_to contain_file_line('cmdline_definition')
            is_expected.to contain_echo('bootloader-apparmor')
              .with(
                'message'  => 'bootloader apparmor',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
