require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::sles::sec_aide' do
  on_supported_os.each do |os, _os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          {
            osfamily: 'Suse',
            operatingsystem: 'SLES',
            architecture: 'x86_64',
            security_baseline: {
              aide: {
                version: '6.1.2',
                status: 'not installed',
              },
            },
          }
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'aide package',
            'log_level' => 'warning',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
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
            is_expected.not_to contain_echo('aide')
          else
            is_expected.not_to contain_package('aide')
            is_expected.not_to contain_exec('aidedb')
            is_expected.not_to contain_exec('rename_aidedb')
            is_expected.to contain_echo('aide')
              .with(
                'message'  => 'aide package',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
