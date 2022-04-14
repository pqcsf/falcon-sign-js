const { getKernel, util } = require('../index');

(async () =>
{
	const falcon = await getKernel('falcon512_n3_v1');
	if(!falcon) 
	{
		return console.log('getKernel fail');;
	}

	console.log(`------------------ genkey ------------------`);
	let key = falcon.genkey();
	if(!key)
	{
		return console.log('genkey fail');
	}

	console.log(`------------------ genkeySeed (${key.genkeySeed.length}) ----------`);
	console.log(util.uint8ArrayToString(key.genkeySeed, 'base64'));
	console.log(`------------------ pk (${key.pk.length}) ------------------`);
	console.log(util.uint8ArrayToString(key.pk, 'base64'));
	console.log(`------------------ sk (${key.sk.length}) ------------------`);
	console.log(util.uint8ArrayToString(key.sk, 'base64'));

	let text = 'TEST MSG';
	let sign = falcon.sign(text, key.sk);
	if(!sign) return console.log('sign fail');
	console.log(`------------------ sign (${sign.length}) ------------------`);
	console.log(util.uint8ArrayToString(sign, 'base64'));
	console.log('------------------ verify ---------------');
	console.log(falcon.verify(sign, text, key.pk));

	let pk = falcon.publicKeyCreate(key.sk);
	console.log(`------------------ create pk (${pk.length}) ------------------`);
	console.log(util.uint8ArrayToString(pk, 'base64'));
	console.log(`------------------ pk eq ------------------`);
	console.log(util.uint8ArrayEqual(pk, key.pk));

	console.log(`------------------ const sign eq ------------------`);
	let constSalt = util.randomBytes(falcon.signSaltByte);
	let constSign1 = falcon.sign(text, key.sk, constSalt);
	let constSign2 = falcon.sign(text, key.sk, constSalt);
	console.log("constSign1 === constSign2 : ", util.uint8ArrayEqual(constSign1, constSign2));
	console.log("randomSign1 === constSign2 : ", util.uint8ArrayEqual(sign, constSign2));
})();
