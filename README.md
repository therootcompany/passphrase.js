# [passphrase.js][passphrasejs] (for browsers)

A ([BIP-39][bip39] compatible) base2048 passphrase generator for browser
JavaScript.

Lightweight. Zero dependencies. 20kb (17kb min, 7.4kb gz) ~150 LoC.

(most of the package weight is due to the base2048 word list)

[bip39]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
[passphrasejs]: https://github.com/therootcompany/passphrase.js

```html
<script src="https://unpkg.com/@root/passphrase"></script>
<script>
  "use strict";

  let Passphrase = window.Passphrase;

  Passphrase.generate(128).then(console.log);
  // often delay margin arch
  // index wrap fault duck
  // club fabric demise scout
</script>
```

| Target Entropy |         Number of Words | Total Bits                             |
| -------------- | ----------------------: | :------------------------------------- |
| 128-bit        | 12 words @ 11 bits each | = 132 bits (128 bits + 4-bit checksum) |
| 160-bit        | 15 words @ 11 bits each | = 165 bits (160 bits + 5-bit checksum) |
| 192-bit        | 18 words @ 11 bits each | = 198 bits (192 bits + 6-bit checksum) |
| 224-bit        | 21 words @ 11 bits each | = 231 bits (224 bits + 7-bit checksum) |
| 256-bit        | 24 words @ 11 bits each | = 264 bits (256 bits + 8-bit checksum) |

## API

- generate
- checksum
- pbkdf2
- base2048.includes

### Passphrase.generate(bitlen)

Generate a "Base2048" passphrase - each word represents 11 bits of entropy.

```js
await Passphrase.generate((bitLen = 128)); // 128, 160, 192, 224, or 256
```

### Passphrase.checksum(passphrase)

We all make mistakes. Especially typos.

Running the checksum can't guarantee that the passphrase is correct, but most
types - such as `brocolli` instead of `broccoli` - will cause it to fail, so
that's a start.

```js
let passphrase = "often delay margin arch ...";
await Passphrase.checksum(passphrase); // true
```

```js
let passphrase = "often delay margin arch TYPO";
await Passphrase.checksum(passphrase).catch(function (err) {
  // checksum failed?
  throw err;
});
```

### Passphrase.pbkdf2(passphrase, other)

Generate a private key seed or encryption key based on the passphrase and some
other string - whether a salt, a password, another passphrase or secret, or an
id of some kind.

```js
await Passphrase.pbkdf2(passphrase, (other = "")); // Uin8Array[32]
```

### Passphrase.base2048.includes(word)

Check if a given word exists in the base2048 dictionary.

```js
Passphrase.base2048.includes("broccoli"); // true
```

```js
Passphrase.base2048.includes("brocolli"); // false
```

#### Get all misspelled words

```js
"hammer spoon brocolli zoo".split(" ").filter(function (word) {
  return word && !Passphrase.base2048.includes(word);
});
// [ "brocolli" ]
```
