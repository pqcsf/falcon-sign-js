API Reference
---

For compatibility with mainstream browsers, the parameters of the functions are Uint8Array instead of Buffer (Nodejs).

The main API consists of three entry points:

	const { getKernel, getKernelNameList, util } = require('falcon-sign');

### `getKernel(algid: string): Promise(<Kernel>)`
Acquisition of core modules for algorithms

### `getKernelNameList(): string[]`
Acquisition of core modules for algorithms

### util: object
Some common utility programs

Kernel
---
The kernel is the interface to the algorithm and contains the following methods.

	const Kernel = await getKernel('falcon512_n3_v1');

### `Kernel.genkey(genkeySeed?: Uint8Array): { genkeySeed: Uint8Array, pk: Uint8Array, sk: Uint8Array } | undefined`

### `Kernel.publicKeyCreate(sk: Uint8Array): Uint8Array | undefined`

### `Kernel.sign(message: Uint8Array | string, sk: Uint8Array, salt?: Uint8Array)): Uint8Array | undefined`

### `Kernel.verify(signMsg: Uint8Array, message: Uint8Array, pk: Uint8Array) : boolean`

There are also the following members

### `Kernel.algid`

### `Kernel.genkeySeedByte`

### `Kernel.skByte`

### `Kernel.pkByte`

### `Kernel.signByte`

### `Kernel.signSaltByte`

### `Kernel.signNonceByte`









