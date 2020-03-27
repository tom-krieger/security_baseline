shared_examples 'common::1.1.1.1' do
  context 'rule 1.1.1.1: cramfs' do
    describe file('/etc/modprobe.d/cramfs.conf') do
      it { should be_file }
      its(:content) { should match /install cramfs \/bin\/true/ }
    end
  end
end
