require 'spec_helper'

describe 'security_baseline::config' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'security_baseline' => {
            'puppet_agent_postrun' => 'postrun_command =',
          },
        )
      end
      let(:params) do
        {
          'update_postrun_command' => true,
        }
      end

      it { is_expected.to compile }
      it do
        is_expected.to contain_exec('set puppet agent postrun agent')
          .with(
            'command' => 'puppet config --section agent set postrun_command "/usr/local/bin/puppet facts upload"',
            'path'    => ['/bin', '/usr/bin', '/usr/local/bin'],
          )

        is_expected.to contain_exec('set puppet agent postrun main')
          .with(
            'command' => 'puppet config --section main set postrun_command "/usr/local/bin/puppet facts upload"',
            'path'    => ['/bin', '/usr/bin', '/usr/local/bin'],
          )

        is_expected.to contain_file('/usr/share/security_baseline/')
          .with(
            'ensure' => 'directory',
            'owner'  => 'root',
            'group'  => 'root',
            'mode'   => '0700',
          )

        is_expected.to contain_file('/usr/share/security_baseline/logs/')
          .with(
            'ensure' => 'directory',
            'owner'  => 'root',
            'group'  => 'root',
            'mode'   => '0700',
          )

        is_expected.to contain_file('/usr/share/security_baseline/bin/')
          .with(
            'ensure' => 'directory',
            'owner'  => 'root',
            'group'  => 'root',
            'mode'   => '0700',
          )

        is_expected.to contain_file('/usr/share/security_baseline/bin/root_path_integrity.sh')
          .with(
            'ensure' => 'present',
            'owner'  => 'root',
            'group'  => 'root',
            'mode'   => '0700',
          )

        is_expected.to contain_file('/usr/share/security_baseline/bin/check_user_home_dirs.sh')
          .with(
            'ensure' => 'present',
            'owner'  => 'root',
            'group'  => 'root',
            'mode'   => '0700',
          )

        is_expected.to contain_file('/usr/share/security_baseline/bin/check_home_dir_permissions.sh')
          .with(
            'ensure' => 'present',
            'owner'  => 'root',
            'group'  => 'root',
            'mode'   => '0700',
          )

        is_expected.to contain_file('/usr/share/security_baseline/bin/check_home_dir_owner.sh')
          .with(
            'ensure' => 'present',
            'owner'  => 'root',
            'group'  => 'root',
            'mode'   => '0700',
          )

        is_expected.to contain_file('/usr/share/security_baseline/bin/check_dot_files_write.sh')
          .with(
            'ensure' => 'present',
            'owner'  => 'root',
            'group'  => 'root',
            'mode'   => '0700',
          )

        is_expected.to contain_file('/usr/share/security_baseline/bin/check_forward_files.sh')
          .with(
            'ensure' => 'present',
            'owner'  => 'root',
            'group'  => 'root',
            'mode'   => '0700',
          )

        is_expected.to contain_file('/usr/share/security_baseline/bin/check_netrc_files.sh')
          .with(
            'ensure' => 'present',
            'owner'  => 'root',
            'group'  => 'root',
            'mode'   => '0700',
          )

        is_expected.to contain_file('/usr/share/security_baseline/bin/check_netrc_files_write.sh')
          .with(
            'ensure' => 'present',
            'owner'  => 'root',
            'group'  => 'root',
            'mode'   => '0700',
          )

        is_expected.to contain_file('/usr/share/security_baseline/bin/root_path_integrity.sh')
          .with(
            'ensure' => 'present',
            'owner'  => 'root',
            'group'  => 'root',
            'mode'   => '0700',
          )

        is_expected.to contain_file('/usr/share/security_baseline/bin/check_rhosts_files.sh')
          .with(
            'ensure' => 'present',
            'owner'  => 'root',
            'group'  => 'root',
            'mode'   => '0700',
          )

        is_expected.to contain_file('/usr/share/security_baseline/bin/check_passwd_group_exist.sh')
          .with(
            'ensure' => 'present',
            'owner'  => 'root',
            'group'  => 'root',
            'mode'   => '0700',
          )
      end
    end
  end
end
