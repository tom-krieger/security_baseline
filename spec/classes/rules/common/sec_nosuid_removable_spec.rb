require 'spec_helper'

describe 'security_baseline::rules::common::sec_nosuid_removable' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'mountpoints' => {
            '/' => {
              'filesystem' => 'ext4',
              'options' => ['rw', 'relatime', 'discard', 'data=ordered'],
            },
            '/usr' => {
              'filesystem' => 'ext4',
              'options' => ['rw', 'relatime', 'discard', 'data=ordered'],
            },
            '/cdrom' => {
              'filesystem' => 'ext4',
              'options' => ['rw', 'relatime', 'discard', 'data=ordered'],
            },
            '/floppy' => {
              'filesystem' => 'ext4',
              'options' => ['rw', 'relatime', 'discard', 'data=ordered'],
            },
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'removeable mounts',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        is_expected.to contain_echo('removable-nosuid /cdrom')
          .with(
            'message'  => 'removeable mounts /cdrom',
            'loglevel' => 'warning',
            'withpath' => false,
          )
        is_expected.to contain_echo('removable-nosuid /floppy')
          .with(
            'message'  => 'removeable mounts /floppy',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      }
    end
  end
end
