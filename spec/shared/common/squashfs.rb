shared_examples 'common::squashfs' do
  context 'rule squashfs' do
    describe file('/etc/modprobe.d/squashfs.conf') do
      it { is_expected.to be_file }
      its(:content) { is_expected.to match %r{install squashfs \/bin\/true} }
    end
  end
end
