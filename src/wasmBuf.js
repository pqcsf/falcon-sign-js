const { isUint8Array, isUint } = require('./util.js');

class WasmBuf 
{
	constructor(kernel, jsBuf)
	{
		this.kernel = kernel;
		if(isUint8Array(jsBuf))
		{
			this.length = jsBuf.length;
		}
		else if(isUint(jsBuf))
		{
			this.length = jsBuf;
		}
		else
		{
			throw new Error('Parameter Error');
		}

		if(this.length > 4294967295) //over uint32
		{
			this.wasmBufPtr = kernel._newByte(this.length & 0xffffffff, this.length >> 32 );
		}
		else 
		{
			this.wasmBufPtr = kernel._newByte(this.length);
		}
		
		if(isUint8Array(jsBuf))
		{
			this.writeJsBuf(jsBuf);
		}
	}

	free() 
	{
		if(!this.wasmBufPtr) 
		{
			throw new Error('Memory is freed');
		}
		this.kernel._freeBuf(this.wasmBufPtr);
		delete this.wasmBufPtr;
	}
	freeSafe()
	{
		if(!this.wasmBufPtr) 
		{
			throw new Error('Memory is freed');
		}
		if(this.length > 4294967295) //over uint32
		{
			this.kernel._freeBufSafe(this.length & 0xffffffff, this.length >> 32);
		}
		else 
		{
			this.kernel._freeBufSafe(this.wasmBufPtr, this.length);
		}
		
		delete this.wasmBufPtr;
	}
	writeJsBuf(source, targetStart=0, sourceStart=0, sourceStartEnd=source.length)
	{
		if(!this.wasmBufPtr) 
		{
			throw new Error('Memory is freed');
		}
		if(sourceStartEnd !== source.length || sourceStart !== 0) 
		{
			source = source.subarray(sourceStart, sourceStartEnd);
		}
		if((source.length + targetStart > this.length))
		{
			throw new Error('Exceeds the memory declaration range');
		}
		this.kernel.HEAPU8.set(source, this.wasmBufPtr + targetStart);
	}
	readJsBuf(length = this.length)
	{
		if(!this.wasmBufPtr) 
		{
			throw new Error('Memory is freed');
		}
		if(length > this.length)
		{
			throw new Error('Exceeds the memory declaration range');
		}
		let tempBuf = new Uint8Array(length);
		tempBuf.set(this.kernel.HEAPU8.subarray(this.wasmBufPtr, this.wasmBufPtr + length) );
		return tempBuf;
	}
}

module.exports = WasmBuf;