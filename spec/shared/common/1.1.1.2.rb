shared_examples 'common::1.1.1.2' do
  context 'rule 1.1.1.2: freexvfs' do
    describe file('/etc/modprobe.d/freevxfs.conf') do
      it { is_expected.to be_file }
      its(:content) { is_expected.to match %r{install freevxfs \/bin\/true} }
    end
  end
end
