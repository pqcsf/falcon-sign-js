const WasmBuf = require('./wasmBuf');
const { isUint8Array, uint8ArrayWriteBigInt64LE, uint8ArrayConcat, uint8ArrayReadUint16BE } = require('./util.js');

let randomBytes;
if (typeof window === 'undefined')
{
	const crypto = require('crypto')
	randomBytes = (size) => 
	{
		return new Uint8Array(crypto.randomBytes(size));
	};
}
else 
{
	randomBytes = (size) => 
	{
		let Buf = new Uint8Array(size);
		crypto.getRandomValues(Buf);
		return Buf;
	};
}
// const textDecoder = new TextDecoder("utf-8");
const textEecoder = new TextEncoder("utf-8");

const namePathTable = 
{
	falcon512_n3_v1: '../kernel/n3_v1/wasmFile/falcon512.js',
	falcon1024_n3_v1: '../kernel/n3_v1/wasmFile/falcon1024.js',
};
const kernelTable = {};

function api(kernel)
{
	return {

		genkey(genkeySeed)
		{
			if(!genkeySeed) 
			{
				genkeySeed = randomBytes(kernel._getGenKeySeedByte());
			}

			let wSeed = new WasmBuf(kernel, kernel._getGenKeySeedByte());
			let wPk = new WasmBuf(kernel, kernel._getPkByte());
			let wSk = new WasmBuf(kernel, kernel._getSkByte());
			wSeed.writeJsBuf(genkeySeed);

			let result = kernel._genkey(wSeed.wasmBufPtr, wPk.wasmBufPtr, wSk.wasmBufPtr);
			if(!result) 
			{
				wSeed.freeSafe();
				wPk.free();
				wSk.freeSafe();
				return;
			}

			let keypair =
			{
				genkeySeed, 
				pk: wPk.readJsBuf(), 
				sk: wSk.readJsBuf(), 
			}
			wSeed.freeSafe();
			wPk.free();
			wSk.freeSafe();
			return keypair
		},
		publicKeyCreate(sk)
		{
			let wSk = new WasmBuf(kernel, sk);
			let wPk = new WasmBuf(kernel, kernel._getPkByte());
			let result = kernel._publicKeyCreate(wSk.wasmBufPtr, wPk.wasmBufPtr);
			if(!result) 
			{
				wPk.free();
				wSk.freeSafe();
				return;
			}

			let pk = wPk.readJsBuf();
			wPk.free();
			wSk.freeSafe();
			return pk;
		},
		sign(message, sk, salt) 
		{
			if(typeof message === 'string')
			{
				message = textEecoder.encode(message);
			}
			if(!salt) 
			{
				salt = randomBytes(kernel._getCryptoSaltByte());
			}

			let wSign = new WasmBuf(kernel, kernel._getCryptoByte());
			let wSk = new WasmBuf(kernel, sk);
			let wSalt = new WasmBuf(kernel, salt);
			let msgLength = new Uint8Array(8);
			uint8ArrayWriteBigInt64LE(msgLength, BigInt(message.length));
			let wMsg = new WasmBuf(kernel, uint8ArrayConcat([msgLength, message]));
			
			let result = kernel._sign(wSign.wasmBufPtr, wMsg.wasmBufPtr, wSk.wasmBufPtr, wSalt.wasmBufPtr);
			if(!result) 
			{
				wSign.free();
				wMsg.free();
				wSk.freeSafe();
				wSalt.freeSafe();
				return;
			}
			
			let signMsg = wSign.readJsBuf();
			let signLen = uint8ArrayReadUint16BE(signMsg) + kernel._getCryptoNonceByte() + 2;
			wSign.free();
			wMsg.free();
			wSk.freeSafe();
			wSalt.freeSafe();
			return signMsg.subarray(0, signLen);
		},
		verify(signMsg, message, pk) 
		{
			if(typeof message === 'string')
			{
				message = textEecoder.encode(message);
			}
			let signMsgLength = uint8ArrayReadUint16BE(signMsg);
			if(signMsgLength + kernel._getCryptoNonceByte() + 2 !== signMsg.length)
			{
				return false;
			}

			let wSign = new WasmBuf(kernel, signMsg);
			let wPk = new WasmBuf(kernel, pk);
			let msgLength = new Uint8Array(8);
			uint8ArrayWriteBigInt64LE(msgLength, BigInt(message.length));
			let wMsg = new WasmBuf(kernel, uint8ArrayConcat([msgLength, message]));

			let result = kernel._verify(wSign.wasmBufPtr, wMsg.wasmBufPtr, wPk.wasmBufPtr);
			wSign.free();
			wMsg.free();
			wPk.free();
			return (result) ? true : false ;
		}
	}
}

function getKernel(name)
{
	if(!kernelTable[name]) 
	{
		if(!namePathTable[name]) 
		{
			return;
		}
		let kernel = require(namePathTable[name]);
		kernelTable[name] = 
		{ 
			initCallback: [], 
			methood: api(kernel),
			init: false
		};
		kernel.onRuntimeInitialized = () => 
		{
			kernelTable[name].init = true;
			for(let i=0; i<kernelTable[name].initCallback.length; i++) 
			{
				kernelTable[name].initCallback[i](kernelTable[name].methood);
			}
		};
	}
	if(!kernelTable[name].init) 
	{	
		return new Promise((res) => 
		{
			kernelTable[name].initCallback.push(res);
		});
	}
	return kernelTable[name].methood;
}

const getKernelNameList = Object.keys(namePathTable);

module.exports = { getKernel, getKernelNameList };