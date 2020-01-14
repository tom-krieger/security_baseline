require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_aide' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
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
          is_expected.to contain_package('aide-common')
            .that_notifies('Exec[aidedb]')
          is_expected.to contain_exec('aidedb')
            .with(
              command: 'aideinit',
            )
            .that_notifies('Exec[rename_aidedb]')
          is_expected.to contain_exec('rename_aidedb')
            .with(
              command: 'mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db',
            )
          is_expected.not_to contain_echo('aide')
        else
          is_expected.not_to contain_package('aide')
          is_expected.not_to contain_package('aide-common')
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
