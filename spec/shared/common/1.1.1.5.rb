shared_examples 'common::1.1.1.5' do
  context 'rule 1.1.1.5: hfsplus' do
    describe file('/etc/modprobe.d/hfsplus.conf') do
      it { is_expected.to be_file }
      its(:content) { is_expected.to match %r{install hfsplus \/bin\/true} }
    end
  end
end
