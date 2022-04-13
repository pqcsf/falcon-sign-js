function isUint8Array(buf)
{
    return buf && buf.BYTES_PER_ELEMENT === 1;
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
	let str = atob(base64Str);
    let buf = new Uint8Array(str.length);
    for (let i=0; i<buf.length; i++) 
	{
        buf[i] = str.charCodeAt(i);
    }
    return buf;
}

function hexStringToUint8Array(hexStr) 
{
	let buf = new Uint8Array(hexStr.length / 2);
	for(let i=0; i<buf.length; i++)
	{
		buf[i] = parseInt(hexStr.substr(i * 2, 2), 16);
	}
	return buf;
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

function uint8ArrayWriteBigInt64LE(bufs, ui64, offset=0)
{
	for(let i=0; i<8; i++)
	{
		bufs[offset + i] = parseInt((ui64 >> BigInt(i * 8)) & (0xffn));
	}

	return ui64;
}

function uint8ArrayReadBigInt64LE(bufs, offset=0)
{
	let ui64 = 0n;
	for(let i=0; i<8; i++)
	{
		ui64 += (BigInt(bufs[i + offset]) << BigInt((i * 8)));
	}

	return ui64;
}

function uint8ArrayReadUint16BE(bufs, offset=0)
{
	return ((bufs[offset] << 8) | bufs[1 + offset]);
}

function uint8ArrayEqual(buf1, buf2)
{
    if (buf1.length != buf2.length) 
	{
		return false;
	}
    for (var i = 0 ; i != buf1.byteLength ; i++)
    {
        if (buf1[i] !== buf1[i]) 
		{
			return false;
		}
    }
    return true;
}

module.exports =
{ 
	isUint8Array, 
	uint8ArrayToString, 
	base64ToUint8Array, 
	hexStringToUint8Array,
	uint8ArrayConcat, 
	uint8ArrayWriteBigInt64LE, 
	uint8ArrayReadBigInt64LE,
	uint8ArrayReadUint16BE,
	uint8ArrayEqual
};