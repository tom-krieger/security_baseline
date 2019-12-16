require 'spec_helper'

describe 'security_baseline::rules::debian::sec_shadow_group' do
  context 'on Debian' do
    let(:facts) do
      {
        osfamily: 'Debian',
        operatingsystem: 'Ubuntu',
        architecture: 'x86_64',
        security_baseline: {
          shadow_group_count: 5,
        },
      }
    end
    let(:params) do
      {
        'enforce' => true,
        'message' => 'shadow group',
        'log_level' => 'warning',
      }
    end

    it {
      is_expected.to compile
      is_expected.to contain_echo('shadow-group')
        .with(
          'message'  => 'shadow group',
          'loglevel' => 'warning',
          'withpath' => false,
        )
    }
  end
end
