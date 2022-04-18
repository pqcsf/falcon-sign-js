function isUint8Array(buf)
{
	return buf && buf.BYTES_PER_ELEMENT === 1;
}

function isUint(v)
{
	return Number.isInteger(v) && (v >= 0);
}

function uint8ArrayToString(buf, decode = 'hex') 
{
	if(decode === 'hex')
	{
		let str = '';
		for(let i=0; i<buf.length; i++) 
		{
			str += (buf[i].toString(16).padStart(2, 0));
		}
		return str;
	}
	else if(decode === 'base64')
	{
		return btoa(String.fromCharCode.apply(null, buf));
	}
}

function base64ToUint8Array(base64Str) 
{
	try 
	{
		let str = atob(base64Str);
		let buf = new Uint8Array(str.length);
		for (let i=0; i<buf.length; i++) 
		{
			buf[i] = str.charCodeAt(i);
		}
		return buf;
	} 
	catch(e) 
	{
		return;
	}
}

function hexStringToUint8Array(hexStr) 
{
	try 
	{
		let buf = new Uint8Array(hexStr.length / 2);
		for(let i=0; i<buf.length; i++)
		{
			buf[i] = parseInt(hexStr.substr(i * 2, 2), 16);
		}
		return buf;
	} 
	catch(e) 
	{
		return;
	}
}

function uint8ArrayConcat(bufs)
{
	let totalSize = 0;
	for(let i=0; i<bufs.length; i++)
	{
		totalSize += bufs[i].length;
	}
	let buf = new Uint8Array(totalSize);
	let offset = 0;
	for(let i=0; i<bufs.length; i++)
	{
		buf.set(bufs[i], offset);
		offset += bufs[i].length;
	}
	return buf;
}

function uint8ArrayWriteBigUInt64LE(buf, ui64, offset=0)
{
	for(let i=0; i<8; i++)
	{
		buf[offset + i] = parseInt((ui64 >> BigInt(i * 8)) & (0xffn));
	}
}

function uint8ArrayReadBigUInt64LE(buf, offset=0)
{
	let ui64 = 0n;
	for(let i=0; i<8; i++)
	{
		ui64 += (BigInt(buf[i + offset]) << BigInt((i * 8)));
	}

	return ui64;
}

function uint8ArrayReadUint16BE(buf, offset=0)
{
	return ((buf[offset] << 8) | buf[1 + offset]);
}

function uint8ArrayEqual(buf1, buf2)
{
	if (buf1.length !== buf2.length) 
	{
		return false;
	}
	for (let i = 0; i<=buf1.length; i++)
	{
		if (buf1[i] !== buf2[i]) 
		{
			return false;
		}
	}
	return true;
}

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

module.exports =
{ 
	isUint8Array,
	isUint,
	uint8ArrayToString,
	base64ToUint8Array,
	hexStringToUint8Array,
	uint8ArrayConcat,
	uint8ArrayWriteBigUInt64LE,
	uint8ArrayReadBigUInt64LE,
	uint8ArrayReadUint16BE,
	uint8ArrayEqual,
	randomBytes
};