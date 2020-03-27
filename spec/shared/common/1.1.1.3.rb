shared_examples 'common::1.1.1.3' do
  context 'rule 1.1.1.3: jffs2' do
    describe file('/etc/modprobe.d/jffs2.conf') do
      it { should be_file }
      its(:content) { should match /install jffs2 \/bin\/true/ }
    end
  end
end