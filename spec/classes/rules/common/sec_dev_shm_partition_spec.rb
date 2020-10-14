# frozen_string_literal: true

require 'spec_helper'

describe 'security_baseline::rules::common::sec_dev_shm_partition' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'security_baseline' => {
            'shm_dir_permissions' => 'xyz',
            'partitions' => {
              'shm' => {
                'nodev' => false,
                'noexec' => false,
                'nosuid' => false,
              },
            },
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => '/dev/shm partition',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        is_expected.to contain_echo('dev-shm-partition')
          .with(
            'message'  => '/dev/shm partition',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      }
    end
  end
end
