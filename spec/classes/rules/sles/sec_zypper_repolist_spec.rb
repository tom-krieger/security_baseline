require 'spec_helper'

describe 'security_baseline::rules::sles::sec_zypper_repolist' do
  context 'on Suse' do
    let(:facts) do
      {
        osfamily: 'Suse',
        operatingsystem: 'SLES',
        architecture: 'x86_64',
        security_baseline: {
          zypper: {
            repolist_config: false,
          },
        },
      }
    end
    let(:params) do
      {
        'enforce' => true,
        'message' => 'repo config',
        'log_level' => 'warning',
      }
    end

    it {
      is_expected.to compile
      is_expected.to contain_echo('package-repo-config')
        .with(
          'message'  => 'repo config',
          'loglevel' => 'warning',
          'withpath' => false,
        )
    }
  end
end
