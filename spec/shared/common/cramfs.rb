shared_examples 'common::cramfs' do
  context 'rule cramfs' do
    describe file('/etc/modprobe.d/cramfs.conf') do
      it { is_expected.to be_file }
      its(:content) { is_expected.to match %r{install cramfs \/bin\/true} }
    end
  end
end
