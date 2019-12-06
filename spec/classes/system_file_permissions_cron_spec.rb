require 'spec_helper'

describe 'security_baseline::system_file_permissions_cron' do
  context 'RedHat' do
    let(:facts) { {
      :osfamily => 'RedHat',
      :operatingsystem => 'CentOS',
      :architecture => 'x86_64',
    } }

    it { is_expected.to compile }

    it do
      is_expected.to contain_file('/usr/local/sbin/system-file-permissions.sh')
        .with(
          'ensure' => 'present',
          'owner'  => 'root',
          'group'  => 'root',
          'mode'   => '0700',
        )

      is_expected.to contain_file('/etc/cron.d/system-file-permissions.cron')
        .with(
          'ensure' => 'present',
          'owner'  => 'root',
          'group'  => 'root',
          'mode'   => '0644',
        )
    end
  end

  context 'Suse' do
    let(:facts) { {
      :osfamily => 'Suse',
      :operatingsystem => 'SLES',
      :architecture => 'x86_64',
    } }

    it { is_expected.to compile }

      it do
        is_expected.to contain_file('/usr/local/sbin/system-file-permissions.sh')
          .with(
            'ensure' => 'present',
            'owner'  => 'root',
            'group'  => 'root',
            'mode'   => '0700',
          )

        is_expected.to contain_file('/etc/cron.d/system-file-permissions.cron')
          .with(
            'ensure' => 'present',
            'owner'  => 'root',
            'group'  => 'root',
            'mode'   => '0644',
          )
      end
  end
end
