shared_examples 'common::udf' do
  context 'rule udf' do
    describe file('/etc/modprobe.d/udf.conf') do
      it { is_expected.to be_file }
      its(:content) { is_expected.to match %r{install udf \/bin\/true} }
    end
  end
end
