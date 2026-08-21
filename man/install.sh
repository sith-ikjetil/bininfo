printf "Installing man page\n"
./render.sh
if [ ! -d "/usr/local/man/man1" ]
then
    sudo mkdir /usr/local/man/man1
fi
sudo cp bininfo.1 /usr/local/man/man1
sudo chmod go+r /usr/local/man/man1/bininfo.1
printf "...install complete\n"
