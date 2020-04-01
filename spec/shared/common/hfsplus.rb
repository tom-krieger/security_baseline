shared_examples 'common::hfsplus' do
  context 'rule hfsplus' do
    describe file('/etc/modprobe.d/hfsplus.conf') do
      it { is_expected.to be_file }
      its(:content) { is_expected.to match %r{install hfsplus \/bin\/true} }
    end
  end
end
