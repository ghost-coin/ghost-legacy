## (note: this is a temporary file, to be added-to by anybody, and moved to release-notes at release time)

Bitcoin Core version 0.16.0 is now available from:

  <https://bitcoincore.org/bin/bitcoin-core-0.16.0/>

This is a new major version release, including new features, various bugfixes
and performance improvements, as well as updated translations.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/bitcoin/bitcoin/issues>

To receive security and update notifications, please subscribe to:

  <https://bitcoincore.org/en/list/announcements/join/>

How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely
shut down (which might take a few minutes for older versions), then run the
installer (on Windows) or just copy over `/Applications/Bitcoin-Qt` (on Mac)
or `bitcoind`/`bitcoin-qt` (on Linux).

The first time you run version 0.15.0 or newer, your chainstate database will be converted to a
new format, which will take anywhere from a few minutes to half an hour,
depending on the speed of your machine.

Note that the block database format also changed in version 0.8.0 and there is no
automatic upgrade code from before version 0.8 to version 0.15.0 or higher. Upgrading
directly from 0.7.x and earlier without re-downloading the blockchain is not supported.
However, as usual, old wallet versions are still supported.

Downgrading warning
-------------------

Wallets created in 0.16 and later are not compatible with versions prior to 0.16
and will not work if you try to use newly created wallets in older versions. Existing
wallets that were created with older versions are not affected by this.

Compatibility
==============

Bitcoin Core is supported and extensively tested on operating systems using
the Linux kernel, macOS 10.10+, and Windows 7 and newer.  It is not recommended
to use Bitcoin Core on unsupported systems.

Bitcoin Core should also work on most other Unix-like systems but is not
frequently tested on them.

From 0.17.0 onwards, macOS <10.10 is no longer supported.  0.17.0 is
built using Qt 5.9.x, which doesn't support versions of macOS older than
10.10.  Additionally, Bitcoin Core does not yet change appearance when
macOS "dark mode" is activated.

In addition to previously-supported CPU platforms, this release's
pre-compiled distribution also provides binaries for the RISC-V
platform.

Notable changes
===============

Example item
------------


Low-level changes
=================

Example item
------------

Credits
=======

Thanks to everyone who directly contributed to this release:

- 251
- Aaron Clauson
- Aaron Golliver
- aaron-hanson
- Adam Langley
- Akio Nakamura
- Akira Takizawa
- Alejandro Avilés
- Alex Morcos
- Alin Rus
- Anditto Heristyo
- Andras Elso
- Andreas Schildbach
- Andrew Chow
- Anthony Towns
- azuchi
- Carl Dong
- Chris Moore
- Chris Stewart
- Christian Gentry
- Cory Fields
- Cristian Mircea Messel
- CryptAxe
- Dan Raviv
- Daniel Edgecumbe
- danra
- david60
- Donal O'Connor
- dongsamb
- Dusty Williams
- Eelis
- esneider
- Evan Klitzke
- fanquake
- Ferdinando M. Ametrano
- fivepiece
- flack
- Florian Schmaus
- gnuser
- Gregory Maxwell
- Gregory Sanders
- Henrik Jonsson
- Jack Grigg
- Jacky C
- James Evans
- James O'Beirne
- Jan Sarenik
- Jeff Rade
- Jeremiah Buddenhagen
- Jeremy Rubin
- Jim Posen
- jjz
- Joe Harvell
- Johannes Kanig
- John Newbery
- Johnson Lau
- Jonas Nick
- Jonas Schnelli
- João Barbosa
- Jorge Timón
- Karel Bílek
- Karl-Johan Alm
- klemens
- Kyuntae Ethan Kim
- laudaa
- Lawrence Nahum
- Lucas Betschart
- Luke Dashjr
- Luke Mlsna
- MarcoFalke
- Mark Friedenbach
- Marko Bencun
- Martin Ankerl
- Matt Corallo
- mruddy
- Murch
- NicolasDorier
- Pablo Fernandez
- Paul Berg
- Pedro Branco
- Pierre Rochard
- Pieter Wuille
- practicalswift
- Randolf Richardson
- Russell Yanofsky
- Samuel Dobson
- Sean Erle Johnson
- Shooter
- Sjors Provoost
- Suhas Daftuar
- Thomas Snider
- Thoragh
- Tim Shimmin
- Tomas van der Wansem
- Utsav Gupta
- Varunram Ganesh
- Vivek Ganesan
- Werner Lemberg
- William Casarin
- Willy Ko
- Wladimir J. van der Laan

As well as everyone that helped translating on [Transifex](https://www.transifex.com/bitcoin/bitcoin/).
