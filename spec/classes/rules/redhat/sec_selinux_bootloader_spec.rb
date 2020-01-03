require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_selinux_bootloader' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'selinux' => {
                'bootloader' => false,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'bootloader selinux',
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
              .that_notifies('Exec[selinux-grub-config]')
            is_expected.to contain_exec('selinux-grub-config')
              .with(
                'command'     => 'grub2-mkconfig -o /boot/grub2/grub.cfg',
                'path'        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'refreshonly' => true,
              )

            is_expected.not_to contain_echo('bootloader-selinux')
          else
            is_expected.not_to contain_file_line('cmdline_definition')
            is_expected.not_to contain_exec('selinux-grub-config')
            is_expected.to contain_echo('bootloader-selinux')
              .with(
                'message'  => 'bootloader selinux',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
