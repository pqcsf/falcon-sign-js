const { isUint8Array } = require('./util.js');

class WasmBuf 
{
	constructor(kernel, jsBuf)
	{
		this.kernel = kernel;
		if(isUint8Array(jsBuf))
		{
			this.length = jsBuf.length;
			this.wasmBufPtr = kernel._newByte(this.length);
			this.writeJsBuf(jsBuf);
		}
		else
		{
			this.length = jsBuf;
			this.wasmBufPtr = kernel._newByte(this.length);
		}
	}

	free() 
	{
		if(!this.wasmBufPtr) 
		{
			throw 'Memory is freed';
		}
		this.kernel._freeBuf(this.wasmBufPtr);
		delete this.wasmBufPtr;
	}
	freeSafe()
	{
		if(!this.wasmBufPtr) 
		{
			throw 'Memory is freed';
		}
		this.kernel._freeBufSafe(this.wasmBufPtr, this.length);
		delete this.wasmBufPtr;
	}
	writeJsBuf(source, targetStart=0, sourceStart=0, sourceStartEnd=source.length)
	{
		if(!this.wasmBufPtr) 
		{
			throw 'Memory is freed';
		}
		for(let i=sourceStart; i<sourceStartEnd; i++)
		{
			this.kernel.HEAPU8[this.wasmBufPtr + targetStart + i] = source[i];
		}
	}
	readJsBuf(length = this.length)
	{
		if(!this.wasmBufPtr) 
		{
			throw 'Memory is freed';
		}
		let tempBuf = new Uint8Array(length);
		for(let i=0; i<length; i++)
		{
			tempBuf[i] = this.kernel.HEAPU8[this.wasmBufPtr + i];
		}
		return tempBuf;
	}
}

module.exports = WasmBuf;