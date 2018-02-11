find ./ -name '*.cpp' | sed -e "s/\.\(.*\)\/.*\.cpp/-I$(pwd | sed 's/\//\\&/g')\1/" | uniq > .syntastic_cpp_config
find ./ -name 'json.hpp' | sed -e "s/\.\(.*\)\/.*\.hpp/-I$(pwd | sed 's/\//\\&/g')\1/" >> .syntastic_cpp_config
pkg-config --cflags r_socket >> .syntastic_cpp_config
pkg-config --cflags unicorn >> .syntastic_cpp_config
