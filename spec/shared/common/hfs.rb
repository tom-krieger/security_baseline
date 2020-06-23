shared_examples 'common::hfs' do
  context 'rule hfs' do
    describe file('/etc/modprobe.d/hfs.conf') do
      it { is_expected.to be_file }
      its(:content) { is_expected.to match %r{install hfs \/bin\/true} }
    end
  end
end
