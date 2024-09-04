const bitcoin = require('bitcoinjs-lib');
const secp256k1 = require('secp256k1');
const worker_threads = require("worker_threads");

class KeyFinder {
    findPrivateKey(targetPublicKeyHex: string, startRangeHex: string, endRangeHex: string): Buffer | null {
        const startRange = BigInt(`0x${startRangeHex}`);
        const endRange = BigInt(`0x${endRangeHex}`);

        const targetPublicKey = Buffer.from(targetPublicKeyHex, 'hex');

        // Iterate over the private key range
        for (let i = startRange; i <= endRange; i++) {
            const keyBuffer = this.bigIntToBuffer(i);
            console.log(`Trying private key: ${keyBuffer.toString('hex')}`);

            if (secp256k1.privateKeyVerify(keyBuffer)) {
                const publicKey = secp256k1.publicKeyCreate(keyBuffer);

                // Compare the generated public key with the target public key
                if (Buffer.compare(publicKey, targetPublicKey) === 0) {
                    console.log(`Corresponding Public Key Found: ${publicKey.toString('hex')}`);
                    return keyBuffer;
                }
            }
        }

        return null;
    }

    // Convert a BigInt to a 32-byte Buffer
    bigIntToBuffer(bigInt: BigInt): Buffer {
        const hex = bigInt.toString(16).padStart(64, '0');
        return Buffer.from(hex, 'hex');
    }

    // Solve the puzzle by searching for the private key
    solvePuzzle(targetPublicKeyHex: string, startRangeHex: string, endRangeHex: string): void {
        console.log("Searching for private key...");

        const privateKeyBuffer = this.findPrivateKey(targetPublicKeyHex, startRangeHex, endRangeHex);

        if (privateKeyBuffer) {
            console.log(`Private key found: ${privateKeyBuffer.toString('hex')}`);
        } else {
            console.log("Private key not found in the given range.");
        }
    }
}

export default { KeyFinder }