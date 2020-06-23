shared_examples 'common::vfat' do
  context 'rule vfat' do
    describe file('/etc/modprobe.d/vfat.conf') do
      it { is_expected.to be_file }
      its(:content) { is_expected.to match %r{install vfat \/bin\/true} }
    end
  end
end
