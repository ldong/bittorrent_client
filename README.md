bittorrent_client
=================

This is another bit torrent client implemented by using python, yet, it is a class project.  :]


1. TODO: write a torrent client using python for class project

    BitTorrent Project Breakdown:

    ~~1. parse torrent 10%~~

    ~~2. hash/handshake 25%~~

    ~~3. parse message 25%~~

    ~~4. request 15%~~

    ~~5. receive blocks 15%~~

    ~~6. combine + verify 10%~~

    Extra Credit

    1. tracker + (1)

    2. multiple peers/threading +++ (3)

    3. resume ++ (2)

    4. sending files +++ (3)

    5. incoming + (1)

2. Only works for torrenting single torrent

    Download uTorrent, select one single file from local machine and seed it.

    install required libs
    ```
    pip install bencode
    pip install requests
    pip install bitstring
    ```
    then run `./client.py file_name.torrent`

    after finishing download, a file_name will appear in the current directory

3. Reference & resources:

    ```
    Python(Recommended):
    http://www.kristenwidman.com/blog/how-to-write-a-bittorrent-client-part-1/
    http://www.kristenwidman.com/blog/how-to-write-a-bittorrent-client-part-2/

    http://phsteve.tumblr.com/post/67371461460/bittorrent
    http://jonas.nitro.dk/bittorrent/bittorrent-rfc.html
    https://wiki.theory.org/BitTorrentSpecification

    ```

