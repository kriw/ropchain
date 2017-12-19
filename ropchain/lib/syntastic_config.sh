find ./ -name '*.cpp' | sed -e "s/\.\(.*\)\/.*\.cpp/-I$(pwd | sed 's/\//\\&/g')\1/" | uniq > .syntastic_cpp_config
