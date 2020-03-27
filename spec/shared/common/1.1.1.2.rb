shared_examples 'common::1.1.1.2' do
  context 'rule 1.1.1.2: freexvfs' do
    describe file('/etc/modprobe.d/freevxfs.conf') do
      it { should be_file }
      its(:content) { should match /install freevxfs \/bin\/true/ }
    end
  end
end