file=$1
save=$(md5sum $1 | cut -d' ' -f1)
dir="./.cache/ropchain/"
[[ -f $dir ]] || mkdir -p $dir
if [ ! -e $save ]
then
    tmpFile='/tmp/tmpGadget.txt'
    rp++ --file=$file --rop=6 > $tmpFile
    sed -i -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" $tmpFile
    grep '0x' $tmpFile |
    grep -v ']' |
    grep 'ret ' |
    sed 's/(.* found)//' > $dir$save
    rm $tmpFile
fi

