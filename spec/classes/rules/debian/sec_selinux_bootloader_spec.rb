require 'spec_helper'

enforce_options = [true, false]
bootloader_options = [false, true]

describe 'security_baseline::rules::debian::sec_selinux_bootloader' do
  enforce_options.each do |enforce|
    bootloader_options.each do |bootloader|
      context "on Ubuntu with enforce = #{enforce}, bootloader = #{bootloader}" do
        let(:pre_condition) do
          <<-EOF
          exec {'selinux-grupb-config':
            command     => 'update-grub',
            path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            refreshonly => true,
          }
          EOF
        end
        let(:facts) do
          {
            osfamily: 'Debian',
            operatingsystem: 'Ubuntu',
            architecture: 'x86_64',
            'security_baseline' => {
              'selinux' => {
                'bootloader' => bootloader,
              },
            },
          }
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
                'command'     => 'update-grub',
                'path'        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'refreshonly' => true,
              )

            is_expected.to contain_kernel_parameter('selinux')
              .with(
                'ensure' => 'present',
                'value'  => '1',
              )
              .that_notifies('Exec[selinux-grub-config]')

            is_expected.to contain_kernel_parameter('security')
              .with(
                'ensure' => 'present',
                'value'  => 'selinux',
              )
              .that_notifies('Exec[selinux-grub-config]')

            is_expected.to contain_kernel_parameter('enforcing')
              .with(
                'ensure' => 'present',
                'value'  => '1',
              )
              .that_notifies('Exec[selinux-grub-config]')

            is_expected.not_to contain_echo('bootloader-selinux')
          else
            is_expected.not_to contain_file_line('cmdline_definition')
            is_expected.not_to contain_exec('selinux-grub-config')
            is_expected.not_to contain_kernel_parameter('selinux')
            is_expected.not_to contain_kernel_parameter('security')
            is_expected.not_to contain_kernel_parameter('enforcing')

            if bootloader == false
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

      context "on Debian with enforce = #{enforce}, bootloader = #{bootloader}" do
        let(:pre_condition) do
          <<-EOF
          exec {'selinux-grupb-config':
            command     => 'update-grub',
            path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            refreshonly => true,
          }
          EOF
        end
        let(:facts) do
          {
            osfamily: 'Debian',
            operatingsystem: 'Debian',
            architecture: 'x86_64',
            'security_baseline' => {
              'selinux' => {
                'bootloader' => bootloader,
              },
            },
          }
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
            if bootloader == false
              is_expected.to contain_exec('activate selinux')
                .with(
                  'command' => 'selinux-activate',
                  'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                )
            end

            is_expected.to contain_file_line('cmdline_definition')
              .with(
                'line'  => 'GRUB_CMDLINE_LINUX_DEFAULT="quiet"',
                'path'  => '/etc/default/grub',
                'match' => '^GRUB_CMDLINE_LINUX_DEFAULT',
              )
              .that_notifies('Exec[selinux-grub-config]')
            is_expected.to contain_exec('selinux-grub-config')
              .with(
                'command'     => 'update-grub',
                'path'        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'refreshonly' => true,
              )

            is_expected.to contain_kernel_parameter('selinux')
              .with(
                'ensure' => 'present',
                'value'  => '1',
              )
              .that_notifies('Exec[selinux-grub-config]')

            is_expected.to contain_kernel_parameter('security')
              .with(
                'ensure' => 'present',
                'value'  => 'selinux',
              )
              .that_notifies('Exec[selinux-grub-config]')

            is_expected.to contain_kernel_parameter('enforcing')
              .with(
                'ensure' => 'present',
                'value'  => '1',
              )
              .that_notifies('Exec[selinux-grub-config]')

            is_expected.not_to contain_echo('bootloader-selinux')
          else
            is_expected.not_to contain_file_line('cmdline_definition')
            is_expected.not_to contain_exec('activate selinux')
            is_expected.not_to contain_exec('selinux-grub-config')
            is_expected.not_to contain_kernel_parameter('selinux')
            is_expected.not_to contain_kernel_parameter('security')
            is_expected.not_to contain_kernel_parameter('enforcing')

            if bootloader == false
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
end
