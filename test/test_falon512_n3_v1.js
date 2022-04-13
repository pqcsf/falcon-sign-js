const { getKernel, util } = require('../index');

(async () =>
{
	const falcon512 = await getKernel('falcon512_n3_v1');
	let key = falcon512.genkey();
	if(!key)
	{
		return;
	}

	console.log(`------------------ genkeySeed (${key.genkeySeed.length}) ----------`);
	console.log(util.uint8ArrayToString(key.genkeySeed, 'base64'));
	console.log(`------------------ pk (${key.pk.length}) ------------------`);
	console.log(util.uint8ArrayToString(key.pk, 'base64'));
	console.log(`------------------ sk (${key.sk.length}) ------------------`);
	console.log(util.uint8ArrayToString(key.sk, 'base64'));

	let text = 'TEST MSG';
	let sign = falcon512.sign(text, key.sk);
	if(!sign) return;

	console.log(`------------------ sign (${sign.length}) ------------------`);
	console.log(util.uint8ArrayToString(sign, 'base64'));
	console.log('------------------ verify ---------------');
	console.log(falcon512.verify(sign, text, key.pk));

	let pk = falcon512.publicKeyCreate(key.sk);
	console.log(`------------------ create pk (${pk.length}) ------------------`);
	console.log(util.uint8ArrayToString(pk, 'base64'));
	console.log(`------------------ pk eq ------------------`);
	console.log(util.uint8ArrayEqual(pk, key.pk));
})();
