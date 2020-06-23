shared_examples 'common::jffs2' do
  context 'rule jffs2' do
    describe file('/etc/modprobe.d/jffs2.conf') do
      it { is_expected.to be_file }
      its(:content) { is_expected.to match %r{install jffs2 \/bin\/true} }
    end
  end
end
