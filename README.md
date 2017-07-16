Privy 1.0
=============

Privy, your secret and secure financial freedom.
--------------

![Logo](doc/privy/privy.png "Logo")

Privy is a private implementation of the "Zerocash" protocol forked from [HUSH](https://www.myhush.com/).

Based on Bitcoin's code, it intends to offer a far higher standard of privacy
through a sophisticated zero-knowledge proving scheme that preserves
confidentiality of transaction metadata. 

This software is the Privy node and command-line client. It downloads and stores the entire history
of Privy transactions; depending on the speed of your computer and network
connection, the synchronization process could take a day or more once the
blockchain has reached a significant size.


**Privy is unfinished and highly experimental.** Use at your own risk!

TEAM
----

* Rob M: [@kururob] Lead Developer

* You can join our team too and make contributions


Building
--------
The following build process generally applies to Ubuntu (and similar) Linux
distributions. For best results it is recommended to use Ubuntu Linux 16.04
or later.
Build Privy along with most dependencies from source by running
Get dependencies:
```{r, engine='bash'}

sudo apt-get install \
      build-essential pkg-config libc6-dev m4 g++-multilib \
      autoconf libtool ncurses-dev unzip git python \
      zlib1g-dev wget bsdmainutils automake
```

Create a Privy configuration file (*important*):
```
mkdir -p ~/.privy
echo "rpcuser=username" >> ~/.privy/privy.conf
echo "rpcpassword=`head -c 32 /dev/urandom | base64`" >>~/.privy/privy.conf
```

Install Privy
```{r, engine='bash'}
# pull
git clone https://github.com/rmoen/privy.git
cd privy
# fetch key
./privyutil/fetch-params.sh
# Build
./privyutil/build.sh -j$(nproc)
# Run a PRIVY node
./src/privyd
```

Currently only Linux is officially supported. Windows/Mac OS X versions are in the works...

Deprecation Policy
------------------

This release is considered deprecated 16 weeks after the release day. There
is an automatic deprecation shutdown feature which will halt the node some
time after this 16 week time period. The automatic feature is based on block
height and can be explicitly disabled.

Where do I begin?
-----------------
As a reference a guide for joining the main Zcash network may be used:
https://github.com/zcash/zcash/wiki/1.0-User-Guide#using-zcash
Users should *not* follow this guide blindly since it applies to ZCash instead of Privy!
The section of using the command line is relevant to Privy.

### Need Help?

* See the documentation at the [Zcash Wiki](https://github.com/zcash/zcash/wiki)
  for help and more general information.

License
-------

For license information see the file [COPYING](COPYING).
