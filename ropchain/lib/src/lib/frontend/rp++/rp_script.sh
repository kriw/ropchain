tmpFile='/tmp/tmpGadget.txt'
rp++ --file=$1 --rop=2 > $tmpFile
# rp++ --file=$1 --rop=6 > $tmpFile
sed -i -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" $tmpFile
grep '0x' $tmpFile |
grep -v 'push' | #avoid using push insn
grep -v 'retn' |
grep -v 'rep' |
grep -v 'xmm' |
grep -v 'set' |
grep -v 'div' | #avoid 0 division
egrep -v '[ge]s[^i]' |
grep -v 'hlt' |
grep 'ret' |
sed 's/(.* found)//'
rm $tmpFile
