# Sharemind KeyDB module

mod_keydb (`libsharemind_mod_keydb.so`) is a Sharemind module that stores data
of SecreC programs in a [Redis][] key-value store. Programs use it through the
[keydb][] and `shared3p_keydb` standard library modules.

## Configuration

See [keydb.conf][] for a commented example configuration.

  [Redis]: https://redis.io/
  [keydb]: https://github.com/sharemind-sdk/secrec-stdlib/blob/master/lib/keydb.sc
  [keydb.conf]: packaging/configs/sharemind/keydb.conf
