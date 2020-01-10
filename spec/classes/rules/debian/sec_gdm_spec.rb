require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_gdm' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'gnome_gdm_conf' => false,
              'gnome_gdm' => true,
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'gdm config',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_file('gdm')
              .with(
                'ensure'  => 'present',
                'path'    => '/etc/gdm3/greeter.dconf-defaults',
                'content' => "[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text=\'Authorized uses only. All activity may be monitored and reported.\'",
              )

            is_expected.to contain_file('banner-login')
              .with(
                'ensure'  => 'present',
                'path'    => '/etc/dconf/db/gdm.d/01-banner-message',
                'content' => "[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text=\'Authorized uses only. All activity may be monitored and reported.\'",
              )
              .that_requires('File[gdm]')
              .that_notifies('Exec[dconf-gdm-exec]')

            is_expected.to contain_exec('dconf-gdm-exec')
              .with(
                'path'        => '/bin/',
                'command'     => 'dconf update',
                'refreshonly' => true,
              )

            is_expected.not_to contain_echo('gdm-conf')
          else
            is_expected.not_to contain_file('gdm')
            is_expected.not_to contain_file('banner-login')
            is_expected.not_to contain_exec('dconf-gdm-exec')
            is_expected.to contain_echo('gdm-conf')
              .with(
                'message'  => 'gdm config',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
