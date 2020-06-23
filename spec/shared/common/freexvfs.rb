shared_examples 'common::freexvfs' do
  context 'rule freexvfs' do
    describe file('/etc/modprobe.d/freevxfs.conf') do
      it { is_expected.to be_file }
      its(:content) { is_expected.to match %r{install freevxfs \/bin\/true} }
    end
  end
end
