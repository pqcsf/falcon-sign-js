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

Usage
---

##### Quick Start (FALCON512)

	const const { getKernel } = require('.');
	(async () => {

	    let Falcon512 = await getKernel('falcon512_n3_v1'); //get falcon512_n3_v1 Kernel
	    //gernkey
	    let keypair = falcon512.genkey(); //return { sk, pk, genKeySeed }
	    //sign
	    let text = 'TEST MSG';
	    let sign = falcon512.sign(text, key.sk);
	    //verify
	    console.log(falcon512.verify(sign, text, key.pk));
	    //create public key by private key
	    let pk = falcon512.publicKeyCreate(key.sk);
	})();








