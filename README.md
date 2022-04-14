Falcon Signature JS
===
The JS module of the post-quantum digital signature algorithm (FALCON).

For more information about the FALCON post-quantum digital signature algorithm, please refer to the following link: [FALCON](https://falcon-sign.info/)


Installation
---

##### from npm

	npm install falcon-sign

##### from git

	git clone git@github.com:pqcsf/falcon-sign-js.git
	cd falcon-sign-js

Quick Start 
---

##### FALCON512:

	const { getKernel } = require('falcon-sign');
	(async () => 
	{
	    let Falcon512 = await getKernel('falcon512_n3_v1'); //get falcon512_n3_v1 Kernel
	    //gernkey
	    let keypair = Falcon512.genkey(); //return { sk, pk, genKeySeed }
	    //sign
	    let text = 'TEST MSG';
	    let sign = Falcon512.sign(text, keypair.sk);
	    //verify
	    console.log(Falcon512.verify(sign, text, keypair.pk));
	    //create public key by private key
	    let pk = Falcon512.publicKeyCreate(keypair.sk);
	})();

##### FALCON1024:
Only the name of getKernel needs to be changed. (falcon512_n3_v1 -> falcon1024_n3_v1)

	const { getKernel } = require('falcon-sign');
	(async () => 
	{
	    let Falcon1024 = await getKernel('falcon1024_n3_v1'); //get falcon512_n3_v1 Kernel
	    //gernkey
	    let keypair = Falcon1024.genkey(); //return { sk, pk, genKeySeed }
	    //sign
	    let text = 'TEST MSG';
	    let sign = Falcon1024.sign(text, keypair.sk);
	    //verify
	    console.log(Falcon1024.verify(sign, text, keypair.pk));
	    //create public key by private key
	    let pk = Falcon1024.publicKeyCreate(keypair.sk);
	})();

##### Use specific seeds to generate key pairs

	let seed = Uint8Array(.....);
	let keypair = Falcon512.genkey();

Seed length according to: Falcon512.genkeySeedByte, different algorithms may have different lengths.

##### Generate the same signature

	const solt = Uint8Array(.....);
	let sign = Falcon512.sign(text, keypair.sk, solt);

Solt length according to: Falcon512.signSaltByte, different algorithms may have different lengths.

API
---
The API is here: [API Reference](api.md)

License
---
The license is here: [License](LICENSE)

Author
---
- **PQCSF** (pqcsecondfoundation@gmail.com)



