# [passphrase.js][passphrasejs] (for browsers)

A ([BIP-39][bip39] compatible) **Base2048 Passphrase & Key Generator** for
browser JavaScript.

Lightweight. Zero dependencies. 20kb (17kb min, 7.4kb gz) ~150 LoC.

(most of the package weight is due to the base2048 word list)

[bip39]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
[passphrasejs]: https://github.com/therootcompany/passphrase.js

```html
<script src="https://unpkg.com/@root/passphrase"></script>
<script type="module">
  "use strict";

  let Passphrase = window.Passphrase;

  let passphrase = await Passphrase.generate(128);
  // often delay margin arch
  // index wrap fault duck
  // club fabric demise scout

  let keyBytes = await Passphrase.pbkdf2(passphrase);
  // Uint8Array[64] (suitable for use with importKey for AES, etc)

  let fooKeyBytes = await Passphrase.pbkdf2(passphrase, "foo");
  // Uint8Array[64] (a completely different key, determined by "foo")
</script>
```

| Target Entropy |         Number of Words | Total Bits                             |
| -------------- | ----------------------: | :------------------------------------- |
| 128-bit        | 12 words @ 11 bits each | = 132 bits (128 bits + 4-bit checksum) |
| 160-bit        | 15 words @ 11 bits each | = 165 bits (160 bits + 5-bit checksum) |
| 192-bit        | 18 words @ 11 bits each | = 198 bits (192 bits + 6-bit checksum) |
| 224-bit        | 21 words @ 11 bits each | = 231 bits (224 bits + 7-bit checksum) |
| 256-bit        | 24 words @ 11 bits each | = 264 bits (256 bits + 8-bit checksum) |

## Features & Use Cases

- [x] Base2048 (BIP-0039 compliant)
- [x] Easy to retype on different devices
- [x] Seed many, distinct keys from a single passphrase
- [x] Keys for AES Encryption & Decryption
- [x] Air Gap security
- [x] Cryptocurrency wallets

## API

- generate
  - encode
- checksum
  - decode
- pbkdf2
- base2048.includes

### Passphrase.generate(bitlen)

Generate a "Base2048" passphrase - each word represents 11 bits of entropy.

```js
await Passphrase.generate(bitLen); // *128*, 160, 192, 224, or 256
```

### Passphrase.encode(bytes)

Encode an array of 16, 20, 24, 28, or 32 bytes (typically a `Uint8Array`) into a
passphrase using the Base2048 word list dictionary.

```js
let bytes = Uint8Array.from([0, 255, 0, 255, 0, 255, 0, 255, 0, 255, 0, 255]);

await Passphrase.encode(bytes);
// "abstract way divert acid useless legend advance theme youth"
```

### Passphrase.checksum(passphrase)

We all make mistakes. Especially typos.

Running the checksum can't guarantee that the passphrase is correct, but most
typos - such as `brocolli` instead of `broccoli` - will cause it to fail, so
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

### Passphrase.decode(words)

Decode an string of space-delimited words from the Base2048 dictionary into a
Uint8Array.

This will throw an error if any non-Base2048-compatible words are used, or if
the checksum does not match.

```js
let words = "abstract way divert acid useless legend advance theme youth";

await Passphrase.decode(words);
// Uint8Array[12] <0, 255, 0, 255, 0, 255, 0, 255, 0, 255, 0, 255>
```

### Passphrase.pbkdf2(passphrase, other)

Generate a private key seed or encryption key based on the passphrase and some
other string - whether a salt, a password, another passphrase or secret, or an
id of some kind.

```js
await Passphrase.pbkdf2(passphrase, other || ""); // Uint8Array[64]
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
