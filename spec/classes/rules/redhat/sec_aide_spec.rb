require 'spec_helper'

describe 'security_baseline::rules::redhat::sec_aide' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }
      let(:params) do
        {
          'enforce' => true,
          'message' => 'aide package',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        is_expected.to contain_package('aide')
          .that_notifies('Exec[aidedb]')
        is_expected.to contain_exec('aidedb')
          .with(
            command: 'aide --init',
          )
          .that_notifies('Exec[rename_aidedb]')
        is_expected.to contain_exec('rename_aidedb')
          .with(
            command: 'mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz',
          )
      end
    end
  end
end
