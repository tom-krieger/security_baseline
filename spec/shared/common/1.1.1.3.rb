shared_examples 'common::1.1.1.3' do
  context 'rule 1.1.1.3: jffs2' do
    describe file('/etc/modprobe.d/jffs2.conf') do
      it { is_expected.to be_file }
      its(:content) { is_expected.to match %r{install jffs2 \/bin\/true} }
    end
  end
end
