file=$1
save=$(md5sum $1 | cut -d' ' -f1)
dir="./.cache/ropchain/"
[[ -f $dir ]] || mkdir -p $dir
if [ ! -e $save ]
then
    rp++ --file=$file --rop=1 |
    grep '0x' |
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" |
    sed 's/(.* found)//' > $dir$save
fi

